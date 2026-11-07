package agent

import (
	"context"

	"github.com/Autumn-27/artex/db"
)

// CredentialSource is the minimal view of the platform credential store that
// domain tools need. It is deliberately narrower than db.CredentialStore so agent
// tests can inject a fake and so the agent package never gains a dependency on
// how secrets are encrypted at rest.
//
// Secrets resolved here are used only to build a subprocess argument; they are
// never placed in a tool result, an activity record, or a graph payload.
type CredentialSource interface {
	Get(ctx context.Context, id int64) (*db.CredentialRecord, error)
	ListByTask(ctx context.Context, taskID int64) ([]*db.CredentialRecord, error)
}

// SetCredentialSource wires the task credential store into this run's tools.
func (t *ToolSet) SetCredentialSource(s CredentialSource) { t.credSource = s }

// SetCredentialSource wires the task credential store into the worker.
func (w *Worker) SetCredentialSource(s CredentialSource) { w.credSource = s }
