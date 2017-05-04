package net.corda.client.rpc

import com.google.common.net.HostAndPort
import net.corda.client.rpc.internal.RPCClient
import net.corda.client.rpc.internal.RPCClientConfiguration
import net.corda.core.messaging.CordaRPCOps
import net.corda.nodeapi.ArtemisTcpTransport.Companion.tcpTransport
import net.corda.nodeapi.ConnectionDirection
import net.corda.nodeapi.config.SSLConfiguration
import java.time.Duration

class CordaRPCConnection internal constructor(
        connection: RPCClient.RPCConnection<CordaRPCOps>
) : RPCClient.RPCConnection<CordaRPCOps> by connection

data class CordaRPCClientConfiguration(
        val connectionMaxRetryInterval: Duration
) {
    internal fun toRpcClientConfiguration(): RPCClientConfiguration {
        return RPCClientConfiguration.default.copy(
                connectionMaxRetryInterval = connectionMaxRetryInterval
        )
    }
    companion object {
        @JvmStatic
        val default = CordaRPCClientConfiguration(
                connectionMaxRetryInterval = RPCClientConfiguration.default.connectionMaxRetryInterval
        )
    }
}

class CordaRPCClient(
        hostAndPort: HostAndPort,
        sslConfiguration: SSLConfiguration? = null,
        configuration: CordaRPCClientConfiguration = CordaRPCClientConfiguration.default
) {
    private val rpcClient = RPCClient<CordaRPCOps>(
            tcpTransport(ConnectionDirection.Outbound(), hostAndPort, sslConfiguration),
            configuration.toRpcClientConfiguration()
    )

    fun start(username: String, password: String): CordaRPCConnection {
        return CordaRPCConnection(rpcClient.start(CordaRPCOps::class.java, username, password))
    }

    inline fun <A> use(username: String, password: String, block: (CordaRPCConnection) -> A): A {
        return start(username, password).use(block)
    }
}