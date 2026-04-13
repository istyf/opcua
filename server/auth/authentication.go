package auth

// AuthenticatedUser contains the authenticated identity information attached to
// a session after successful user authentication.
//
// This structure is intentionally focused on identity data needed by the
// server today. Extra backend-specific data can be attached through
// Attributes. Role assignment will be added later as a follow-on feature.
type AuthenticatedUser struct {
	UserName string
	Subject  string

	Attributes map[string]any
}
