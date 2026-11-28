package msfrpc

import (
	"context"
	"strings"
	"time"
)

// RunConsole creates a console, feeds it script, and polls console.read until
// stop says the output is complete (or wait expires). msfrpcd's console is the
// only way to run a module with arbitrary options — module.execute accepts just
// the core ones — so this is the workhorse of both msf_execute and autopwn.
//
// stop receives the accumulated output and the console's current busy flag;
// returning true ends the poll. A nil stop finishes as soon as the console has
// produced output and gone idle, which covers `version`, `show options`, etc.
func (c *Client) RunConsole(ctx context.Context, script string, wait time.Duration, stop func(output string, busy bool) bool) (string, error) {
	id, err := c.ConsoleCreate(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.ConsoleDestroy(ctx, id) }()

	if err := c.ConsoleWrite(ctx, id, script); err != nil {
		return "", err
	}
	if wait <= 0 {
		wait = 30 * time.Second
	}
	deadline := time.Now().Add(wait)
	var out strings.Builder
	idle := 0
	for {
		data, busy, readErr := c.ConsoleRead(ctx, id)
		if readErr == nil && data != "" {
			out.WriteString(data)
			idle = 0
		}
		if stop != nil {
			if stop(out.String(), busy) {
				return out.String(), nil
			}
		} else if out.Len() > 0 && !busy {
			// One extra quiet poll keeps trailing lines that arrive with the
			// prompt from being dropped.
			if idle++; idle >= 2 {
				return out.String(), nil
			}
		}
		if time.Now().After(deadline) {
			return out.String(), nil
		}
		select {
		case <-ctx.Done():
			return out.String(), ctx.Err()
		case <-time.After(400 * time.Millisecond):
		}
	}
}
