package net.corda.node.services.messaging

import com.esotericsoftware.kryo.Kryo
import com.esotericsoftware.kryo.Serializer
import com.esotericsoftware.kryo.io.Input
import com.esotericsoftware.kryo.io.Output
import com.esotericsoftware.kryo.pool.KryoPool
import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import com.google.common.cache.RemovalListener
import com.google.common.collect.HashMultimap
import com.google.common.collect.Multimaps
import com.google.common.collect.SetMultimap
import com.google.common.util.concurrent.ThreadFactoryBuilder
import net.corda.core.ErrorOr
import net.corda.core.crypto.commonName
import net.corda.core.messaging.RPCOps
import net.corda.core.random63BitValue
import net.corda.core.serialization.KryoPoolWithContext
import net.corda.core.utilities.LazyStickyPool
import net.corda.core.utilities.debug
import net.corda.core.utilities.loggerFor
import net.corda.node.services.RPCUserService
import net.corda.nodeapi.*
import net.corda.nodeapi.ArtemisMessagingComponent.Companion.NODE_USER
import org.apache.activemq.artemis.api.core.Message
import org.apache.activemq.artemis.api.core.SimpleString
import org.apache.activemq.artemis.api.core.client.ActiveMQClient.DEFAULT_ACK_BATCH_SIZE
import org.apache.activemq.artemis.api.core.client.ClientConsumer
import org.apache.activemq.artemis.api.core.client.ClientMessage
import org.apache.activemq.artemis.api.core.client.ServerLocator
import org.apache.activemq.artemis.api.core.management.ActiveMQServerControl
import org.apache.activemq.artemis.api.core.management.CoreNotificationType
import org.apache.activemq.artemis.api.core.management.ManagementHelper
import org.bouncycastle.asn1.x500.X500Name
import rx.Notification
import rx.Observable
import rx.Subscriber
import rx.Subscription
import java.lang.reflect.InvocationTargetException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

data class RPCServerConfiguration(
        /** The number of threads to use for handling RPC requests */
        val rpcThreadPoolSize: Int,
        /** The number of consumers to handle incoming messages */
        val consumerPoolSize: Int,
        /** The maximum number of producers to create to handle outgoing messages */
        val producerPoolBound: Int,
        /** The interval of subscription reaping in milliseconds */
        val reapIntervalMs: Long
) {
    companion object {
        val default = RPCServerConfiguration(
                rpcThreadPoolSize = 4,
                consumerPoolSize = 2,
                producerPoolBound = 4,
                reapIntervalMs = 1000
        )
    }
}

/**
 * The [RPCServer] implements the complement of [RPCClient]. When an RPC request arrives it dispatches to the
 * corresponding function in [ops]. During serialisation of the reply (and later observations) the server subscribes to
 * each Observable it encounters and captures the client address to associate with these Observables. Later it uses this
 * address to forward observations arriving on the Observables.
 *
 * The way this is done is similar to that in [RPCClient], we use Kryo and add a context to stores the subscription map.
 */
class RPCServer(
        private val ops: RPCOps,
        private val rpcServerUsername: String,
        private val rpcServerPassword: String,
        private val serverLocator: ServerLocator,
        private val userService: RPCUserService,
        private val nodeLegalName: String,
        private val rpcConfiguration: RPCServerConfiguration = RPCServerConfiguration.default
) {
    private companion object {
        val log = loggerFor<RPCServer>()
        val kryoPool = KryoPool.Builder { RPCKryo(RpcServerObservableSerializer) }.build()
    }
    // The methodname->Method map to use for dispatching.
    private val methodTable = ops.javaClass.declaredMethods.groupBy { it.name }.mapValues { it.value.single() }
    // The observable subscription mapping.
    private val observableMap = createObservableSubscriptionMap()
    // A mapping from client addresses to IDs of associated Observables
    private val clientAddressToObservables = Multimaps.synchronizedSetMultimap(HashMultimap.create<SimpleString, RPCApi.ObservableId>())
    // The scheduled reaper handle.
    private lateinit var reaperScheduledFuture: ScheduledFuture<*>

    private val observationSendExecutor = Executors.newFixedThreadPool(
            1,
            ThreadFactoryBuilder().setNameFormat("rpc-observation-sender-%d").build()
    )

    private val rpcExecutor = Executors.newScheduledThreadPool(
            rpcConfiguration.rpcThreadPoolSize,
            ThreadFactoryBuilder().setNameFormat("rpc-server-handler-pool-%d").build()
    )

    private val reaperExecutor = Executors.newScheduledThreadPool(
            1,
            ThreadFactoryBuilder().setNameFormat("rpc-server-reaper-%d").build()
    )

    private val sessionAndConsumers = ArrayList<ArtemisConsumer>(rpcConfiguration.consumerPoolSize)
    private val sessionAndProducerPool = LazyStickyPool(rpcConfiguration.producerPoolBound) {
        val sessionFactory = serverLocator.createSessionFactory()
        val session = sessionFactory.createSession(rpcServerUsername, rpcServerPassword, false, true, true, false, DEFAULT_ACK_BATCH_SIZE)
        session.start()
        ArtemisProducer(sessionFactory, session, session.createProducer())
    }
    private lateinit var clientBindingRemovalConsumer: ClientConsumer
    private lateinit var serverControl: ActiveMQServerControl

    private fun createObservableSubscriptionMap(): ObservableSubscriptionMap {
        val onObservableRemove = RemovalListener<RPCApi.ObservableId, ObservableSubscription> {
            log.debug { "Unsubscribing from Observable with id ${it.key} because of ${it.cause}" }
            it.value.subscription.unsubscribe()
        }
        return CacheBuilder.newBuilder().removalListener(onObservableRemove).build()
    }

    fun start(activeMqServerControl: ActiveMQServerControl) {
        log.info("Starting RPC server with configuration $rpcConfiguration")
        reaperScheduledFuture = reaperExecutor.scheduleAtFixedRate(
                this::reapSubscriptions,
                rpcConfiguration.reapIntervalMs,
                rpcConfiguration.reapIntervalMs,
                TimeUnit.MILLISECONDS
        )
        for (i in 1 .. rpcConfiguration.consumerPoolSize) {
            val sessionFactory = serverLocator.createSessionFactory()
            val session = sessionFactory.createSession(rpcServerUsername, rpcServerPassword, false, true, true, false, DEFAULT_ACK_BATCH_SIZE)
            val consumer = session.createConsumer(RPCApi.RPC_SERVER_QUEUE_NAME)
            consumer.setMessageHandler(this@RPCServer::clientArtemisMessageHandler)
            session.start()
            sessionAndConsumers.add(ArtemisConsumer(sessionFactory, session, consumer))
        }
        clientBindingRemovalConsumer = sessionAndConsumers[0].session.createConsumer(RPCApi.RPC_CLIENT_BINDING_REMOVALS)
        clientBindingRemovalConsumer.setMessageHandler(this::bindingRemovalArtemisMessageHandler)
        serverControl = activeMqServerControl
    }

    fun close() {
        reaperScheduledFuture.cancel(false)
        rpcExecutor.shutdownNow()
        reaperExecutor.shutdownNow()
        rpcExecutor.awaitTermination(500, TimeUnit.MILLISECONDS)
        reaperExecutor.awaitTermination(500, TimeUnit.MILLISECONDS)
        sessionAndConsumers.forEach {
            it.consumer.close()
            it.session.close()
            it.sessionFactory.close()
        }
        observableMap.invalidateAll()
        reapSubscriptions()
        sessionAndProducerPool.close().forEach {
            it.producer.close()
            it.session.close()
            it.sessionFactory.close()
        }
    }

    private fun bindingRemovalArtemisMessageHandler(artemisMessage: ClientMessage) {
        val notificationType = artemisMessage.getStringProperty(ManagementHelper.HDR_NOTIFICATION_TYPE)
        require(notificationType == CoreNotificationType.BINDING_REMOVED.name)
        val clientAddress = artemisMessage.getStringProperty(ManagementHelper.HDR_ROUTING_NAME)
        log.warn("Detected RPC client disconnect on address $clientAddress, scheduling for reaping")
        invalidateClient(SimpleString(clientAddress))
    }

    // Note that this function operates on the *current* view of client observables. During invalidation further
    // Observables may be serialised and thus registered.
    private fun invalidateClient(clientAddress: SimpleString) {
        val observableIds = clientAddressToObservables.removeAll(clientAddress)
        observableMap.invalidateAll(observableIds)
    }

    private fun clientArtemisMessageHandler(artemisMessage: ClientMessage) {
        val clientToServer = RPCApi.ClientToServer.fromClientMessage(kryoPool, artemisMessage)
        log.debug { "-> RPC -> $clientToServer" }
        when (clientToServer) {
            is RPCApi.ClientToServer.RpcRequest -> {
                val rpcContext = RpcContext(
                        currentUser = getUser(artemisMessage)
                )
                rpcExecutor.submit {
                    val result = ErrorOr.catch {
                        try {
                            CURRENT_RPC_CONTEXT.set(rpcContext)
                            log.debug { "Calling ${clientToServer.methodName}" }
                            val method = methodTable[clientToServer.methodName] ?:
                                    throw RPCException("Received RPC for unknown method ${clientToServer.methodName} - possible client/server version skew?")
                            method.invoke(ops, *clientToServer.arguments.toTypedArray())
                        } finally {
                            CURRENT_RPC_CONTEXT.remove()
                        }
                    }
                    val resultWithExceptionUnwrapped = result.mapError {
                        if (it is InvocationTargetException) {
                            it.cause ?: RPCException("Caught InvocationTargetException without cause")
                        } else {
                            it
                        }
                    }
                    val reply = RPCApi.ServerToClient.RpcReply(
                            id = clientToServer.id,
                            result = resultWithExceptionUnwrapped
                    )
                    val observableContext = ObservableContext(
                            clientToServer.id,
                            observableMap,
                            clientAddressToObservables,
                            clientToServer.clientAddress,
                            serverControl,
                            sessionAndProducerPool,
                            observationSendExecutor,
                            kryoPool
                    )
                    observableContext.sendMessage(reply)
                }
            }
            is RPCApi.ClientToServer.ObservablesClosed -> {
                observableMap.invalidateAll(clientToServer.ids)
            }
        }
        artemisMessage.acknowledge()
    }

    private fun reapSubscriptions() {
        observableMap.cleanUp()
    }

    // TODO remove this User once webserver doesn't need it
    private val nodeUser = User(NODE_USER, NODE_USER, setOf())
    private fun getUser(message: ClientMessage): User {
        val validatedUser = message.getStringProperty(Message.HDR_VALIDATED_USER) ?: throw IllegalArgumentException("Missing validated user from the Artemis message")
        val rpcUser = userService.getUser(validatedUser)
        if (rpcUser != null) {
            return rpcUser
        } else if (X500Name(validatedUser).commonName == nodeLegalName) {
            return nodeUser
        } else {
            throw IllegalArgumentException("Validated user '$validatedUser' is not an RPC user nor the NODE user")
        }
    }
}

@JvmField
internal val CURRENT_RPC_CONTEXT: ThreadLocal<RpcContext> = ThreadLocal()
fun getRpcContext(): RpcContext = CURRENT_RPC_CONTEXT.get()

/**
 * @param currentUser This is available to RPC implementations to query the validated [User] that is calling it. Each
 *     user has a set of permissions they're entitled to which can be used to control access.
 */
data class RpcContext(
        val currentUser: User
)

class ObservableSubscription(
        val subscription: Subscription
)

typealias ObservableSubscriptionMap = Cache<RPCApi.ObservableId, ObservableSubscription>

// We construct an observable context on each RPC request. If subsequently a nested Observable is
// encountered this same context is propagated by the instrumented KryoPool. This way all
// observations rooted in a single RPC will be muxed correctly. Note that the context construction
// itself is quite cheap.
class ObservableContext(
        val rpcRequestId: RPCApi.RpcRequestId,
        val observableMap: ObservableSubscriptionMap,
        val clientAddressToObservables: SetMultimap<SimpleString, RPCApi.ObservableId>,
        val clientAddress: SimpleString,
        val serverControl: ActiveMQServerControl,
        val sessionAndProducerPool: LazyStickyPool<ArtemisProducer>,
        val observationSendExecutor: ExecutorService,
        kryoPool: KryoPool
) {
    private companion object {
        val log = loggerFor<ObservableContext>()
    }

    private val kryoPoolWithObservableContext = RpcServerObservableSerializer.createPoolWithContext(kryoPool, this)
    fun sendMessage(serverToClient: RPCApi.ServerToClient) {
        try {
            sessionAndProducerPool.run(rpcRequestId) {
                val artemisMessage = it.session.createMessage(false)
                serverToClient.writeToClientMessage(kryoPoolWithObservableContext, artemisMessage)
                it.producer.send(clientAddress, artemisMessage)
                log.debug("<- RPC <- $serverToClient")
            }
        } catch (throwable: Throwable) {
            log.error("Failed to send message, kicking client. Message was $serverToClient", throwable)
            serverControl.closeConsumerConnectionsForAddress(clientAddress.toString())
        }
    }
}

private object RpcServerObservableSerializer : Serializer<Observable<Any>>() {
    private object RpcObservableContextKey
    private val log = loggerFor<RpcServerObservableSerializer>()

    fun createPoolWithContext(kryoPool: KryoPool, observableContext: ObservableContext): KryoPool {
        return KryoPoolWithContext(kryoPool, RpcObservableContextKey, observableContext)
    }

    override fun read(kryo: Kryo?, input: Input?, type: Class<Observable<Any>>?): Observable<Any> {
        throw UnsupportedOperationException()
    }

    override fun write(kryo: Kryo, output: Output, observable: Observable<Any>) {
        val observableId = RPCApi.ObservableId(random63BitValue())
        val observableContext = kryo.context[RpcObservableContextKey] as ObservableContext
        output.writeLong(observableId.toLong, true)
        val observableWithSubscription = ObservableSubscription(
                // We capture [observableContext] in the subscriber. Note that all synchronisation/kryo borrowing
                // must be done again within the subscriber
                subscription = observable.materialize().subscribe(
                        object : Subscriber<Notification<Any>>() {
                            override fun onNext(observation: Notification<Any>) {
                                if (!isUnsubscribed) {
                                    observableContext.observationSendExecutor.submit {
                                        observableContext.sendMessage(RPCApi.ServerToClient.Observation(observableId, observation))
                                    }
                                }
                            }
                            override fun onError(exception: Throwable) {
                                log.error("onError called in materialize()d RPC Observable", exception)
                            }
                            override fun onCompleted() {
                            }
                        }
                )
        )
        observableContext.clientAddressToObservables.put(observableContext.clientAddress, observableId)
        observableContext.observableMap.put(observableId, observableWithSubscription)
    }
}