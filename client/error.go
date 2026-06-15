package client

// APIError carries an HTTP status code alongside the message so the API layer
// can map upstream/lookup failures to the right response code.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return e.Message }

func NewAPIError(status int, message string) *APIError {
	return &APIError{Status: status, Message: message}
}
