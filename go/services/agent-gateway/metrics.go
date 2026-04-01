package agent_gateway

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Compound authorization decisions by result and denying component
	agentAuthDecisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stratium_agent_auth_decisions_total",
		Help: "Total compound authorization decisions by result and component",
	}, []string{"result", "denied_by"})

	// Latency of compound policy evaluation
	agentAuthLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "stratium_agent_auth_latency_seconds",
		Help:    "Latency of compound policy evaluation",
		Buckets: prometheus.DefBuckets,
	})

	// Currently active delegations
	agentDelegationsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "stratium_agent_delegations_active",
		Help: "Currently active (non-expired, non-revoked) delegations",
	})

	// Total delegations created
	agentDelegationsCreatedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "stratium_agent_delegations_created_total",
		Help: "Total delegations created",
	})

	// Total agent actions by tool, tier, and result
	agentActionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stratium_agent_actions_total",
		Help: "Total agent actions by tool, tier, and result",
	}, []string{"tool", "tier", "result"})

	// Action validation failures by reason
	agentValidationFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stratium_agent_validation_failures_total",
		Help: "Action validation failures by reason",
	}, []string{"reason"})

	// Privilege amplification attempts (agent ALLOW + user DENY)
	agentPrivilegeAmplificationAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "stratium_agent_privilege_amplification_attempts",
		Help: "Cases where agent ALLOW + user DENY detected (proxy abuse attempts)",
	})

	// Delegation chain depth distribution
	agentChainDepth = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "stratium_agent_chain_depth",
		Help:    "Delegation chain depth distribution",
		Buckets: []float64{0, 1, 2, 3, 4, 5},
	})

	// Chain denials by depth
	agentChainDeniedAtDepth = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stratium_agent_chain_denied_at_depth",
		Help: "Chain denials by depth",
	}, []string{"depth"})

	// Chain revocations with cascade count
	agentChainRevocationsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "stratium_agent_chain_revocations_total",
		Help: "Total chain revocations (including cascades)",
	})

	// Scope widening attempts
	agentScopeWideningAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "stratium_agent_scope_widening_attempts",
		Help: "Attempts to create child delegation exceeding parent scope",
	})
)
