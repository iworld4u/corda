package net.corda.node.services.api

import net.corda.core.flows.FlowLogic
import net.corda.core.flows.SecurityIdentifier
import net.corda.core.flows.StateMachineRunId
import net.corda.core.serialization.SingletonSerializeAsToken
import net.corda.core.utilities.ProgressTracker
import java.time.Instant

/**
 * Minimum event specific data for any audit event to be logged. It is expected that the underlying audit service
 * will enrich this to include details of the node, so that in clustered configurations the source node can be identified.
 */
interface SystemAuditEvent {
    /**
     * The UTC time point at which the audit event happened.
     */
    val timestamp: Instant
    /**
     * The responsible individual, node, or subsystem to which the audit event can be mapped.
     */
    val principal: SecurityIdentifier
    /**
     * The specific class of audit event being recorded.
     */
    val auditEventType: String
    /**
     * A human readable description of audit event including any permission check results.
     */
    val description: String
    /**
     * Further tagged details that should be recorded along with the common data of the audit event.
     */
    val contextData: Map<String, String>
}

/**
 * Simple concrete data class implementation of SystemAuditEvent
 */
data class SystemAuditEventImpl(override val timestamp: Instant,
                                override val principal: SecurityIdentifier,
                                override val auditEventType: String,
                                override val description: String,
                                override val contextData: Map<String, String>) : SystemAuditEvent

/**
 * Extension of SystemAuditEvent interface to include information needed to trace an audit event back to a specific flow.
 */
interface FlowAuditEvent : SystemAuditEvent {
    /**
     * The concrete type of FlowLogic being referenced.
     * TODO This should be replaced with the fully versioned name/signature of the flow.
     */
    val flowType: Class<out FlowLogic<*>>
    /**
     * The stable identifier of the flow as stored with Checkpoints.
     */
    val flowId: StateMachineRunId
}

/**
 * Marker interface extension of FlowAuditEvent to capture the initiation of a new flow.
 * The flow parameters should be captured to the context data.
 */
interface FlowStartEvent : FlowAuditEvent {
}

/**
 * Extension of FlowAuditEvent to include ProgressTracker Step object whenever a change is signalled.
 * The API for ProgressTracker has been extended so that the Step can contain some extra context data,
 * which is copied into the contextData Map.
 */
interface FlowProgressAuditEvent : FlowAuditEvent {
    val flowProgress: ProgressTracker.Step
}

/**
 * Extension of FlowAuditEvent to record any FlowExceptions, or other unexpected terminations of a Flow.
 */
interface FlowErrorAuditEvent : FlowAuditEvent {
    val error: Throwable
}

/**
 * Extension of FlowAuditEvent to record checks on per flow permissions and the verdict of these checks
 * If the permission is denied i.e. permissionGranted is false, then it is expected that the flow will be terminated immediately
 * after recording the FlowPermissionAuditEvent. This may cause an extra FlowErrorAuditEvent to be recorded too.
 */
interface FlowPermissionAuditEvent : FlowAuditEvent {
    val permissionRequested: String
    val permissionGranted: Boolean
}

/**
 * Simple concrete data class implementation of FlowAuditEvent
 */
data class FlowAuditEventImpl(override val timestamp: Instant,
                              override val principal: SecurityIdentifier,
                              override val auditEventType: String,
                              override val description: String,
                              override val contextData: Map<String, String>,
                              override val flowType: Class<out FlowLogic<*>>,
                              override val flowId: StateMachineRunId) : FlowAuditEvent

/**
 * Simple concrete data class implementation of FlowStartEvent
 */
data class FlowStartEventImpl(override val timestamp: Instant,
                              override val principal: SecurityIdentifier,
                              override val auditEventType: String,
                              override val description: String,
                              override val contextData: Map<String, String>,
                              override val flowType: Class<out FlowLogic<*>>,
                              override val flowId: StateMachineRunId) : FlowStartEvent


/**
 * Simple concrete data class implementation of FlowProgressAuditEvent
 */
data class FlowProgressAuditEventImpl(override val timestamp: Instant,
                                      override val principal: SecurityIdentifier,
                                      override val auditEventType: String,
                                      override val description: String,
                                      override val flowType: Class<out FlowLogic<*>>,
                                      override val flowId: StateMachineRunId,
                                      override val flowProgress: ProgressTracker.Step) : FlowProgressAuditEvent {
    override val contextData: Map<String, String> get() = flowProgress.extraAuditData
}

/**
 * Simple concrete data class implementation of FlowErrorAuditEvent
 */
data class FlowErrorAuditEventImpl(override val timestamp: Instant,
                                   override val principal: SecurityIdentifier,
                                   override val auditEventType: String,
                                   override val description: String,
                                   override val contextData: Map<String, String>,
                                   override val flowType: Class<out FlowLogic<*>>,
                                   override val flowId: StateMachineRunId,
                                   override val error: Throwable) : FlowErrorAuditEvent


/**
 * Simple concrete data class implementation of FlowPermissionAuditEvent
 */
data class FlowPermissionAuditEventImpl(override val timestamp: Instant,
                                        override val principal: SecurityIdentifier,
                                        override val auditEventType: String,
                                        override val description: String,
                                        override val contextData: Map<String, String>,
                                        override val flowType: Class<out FlowLogic<*>>,
                                        override val flowId: StateMachineRunId,
                                        override val permissionRequested: String,
                                        override val permissionGranted: Boolean) : FlowPermissionAuditEvent

/**
 * Minimal interface for recording audit information within the system. The AuditService is assumed to be available only
 * to trusted internal components via ServiceHubInternal.
 */
interface AuditService {
    fun recordSystemAuditEvent(event: SystemAuditEvent)
}

/**
 * Empty do nothing AuditService as placeholder.
 * TODO Write a full implementation that expands all the audit events to the database.
 */
class DummyAuditService : AuditService, SingletonSerializeAsToken() {
    override fun recordSystemAuditEvent(event: SystemAuditEvent) {
        //TODO Implement transformation of the audit events to formal audit data
    }
}

