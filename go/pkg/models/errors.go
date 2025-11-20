package models

import "errors"

var (
	// Policy errors
	ErrPolicyNotFound         = errors.New("policy not found")
	ErrPolicyAlreadyExists    = errors.New("policy already exists")
	ErrInvalidPolicyName      = errors.New("invalid policy name")
	ErrInvalidPolicyContent   = errors.New("invalid policy content")
	ErrInvalidPolicyLanguage  = errors.New("invalid policy language")
	ErrInvalidPolicyEffect    = errors.New("invalid policy effect")
	ErrPolicyEvaluationFailed = errors.New("policy evaluation failed")

	// Entitlement errors
	ErrEntitlementNotFound         = errors.New("entitlement not found")
	ErrEntitlementAlreadyExists    = errors.New("entitlement already exists")
	ErrInvalidEntitlementName      = errors.New("invalid entitlement name")
	ErrInvalidSubjectAttributes    = errors.New("invalid subject attributes")
	ErrInvalidResourceAttributes   = errors.New("invalid resource attributes")
	ErrInvalidActions              = errors.New("invalid actions")
	ErrEntitlementExpired          = errors.New("entitlement expired")
	ErrEntitlementEvaluationFailed = errors.New("entitlement evaluation failed")

	// Repository errors
	ErrDatabaseConnection = errors.New("database connection failed")
	ErrDatabaseQuery      = errors.New("database query failed")
	ErrDatabaseInsert     = errors.New("database insert failed")
	ErrDatabaseUpdate     = errors.New("database update failed")
	ErrDatabaseDelete     = errors.New("database delete failed")

	// General errors
	ErrInvalidInput      = errors.New("invalid input")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrForbidden         = errors.New("forbidden")
	ErrInternalServer    = errors.New("internal server error")
	ErrNotImplemented    = errors.New("not implemented")
)