package telemetry

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type Metrics struct {
	ConnectionsTotal      atomic.Uint64
	ConnectionsActive     atomic.Int64
	SessionErrorsTotal    atomic.Uint64
	ProtectedStatements   atomic.Uint64
	ParametersTransformed atomic.Uint64
	ResultValuesDecrypted atomic.Uint64
}

func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = fmt.Fprintf(writer, `# HELP pgkms_connections_total Accepted PostgreSQL connections.
# TYPE pgkms_connections_total counter
pgkms_connections_total %d
# HELP pgkms_connections_active Active PostgreSQL connections.
# TYPE pgkms_connections_active gauge
pgkms_connections_active %d
# HELP pgkms_session_errors_total Sessions terminated by gateway or protocol errors.
# TYPE pgkms_session_errors_total counter
pgkms_session_errors_total %d
# HELP pgkms_protected_statements_total Statements whose plans touch protected data.
# TYPE pgkms_protected_statements_total counter
pgkms_protected_statements_total %d
# HELP pgkms_parameters_transformed_total Bind parameter values encrypted or indexed.
# TYPE pgkms_parameters_transformed_total counter
pgkms_parameters_transformed_total %d
# HELP pgkms_result_values_decrypted_total Result values selected for decryption.
# TYPE pgkms_result_values_decrypted_total counter
pgkms_result_values_decrypted_total %d
`, m.ConnectionsTotal.Load(), m.ConnectionsActive.Load(), m.SessionErrorsTotal.Load(), m.ProtectedStatements.Load(), m.ParametersTransformed.Load(), m.ResultValuesDecrypted.Load())
	})
}
