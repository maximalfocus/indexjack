package verify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"time"

	"indexjack/internal/fixtures"
	"indexjack/internal/registry"
)

// Stack is every checked-in registry fixture set running in this process on
// loopback.
//
// It exists so the whole gate can be verified without a container network,
// and so tests can observe requests at the registry boundary rather than
// believing a resolver's account of what it asked for.
type Stack struct {
	// Endpoints maps each registry's checked-in in-network URL to the
	// loopback URL it is actually reachable at.
	Endpoints map[string]string
	// Handlers is each registry's request-observing handler, keyed by
	// fixture set id.
	Handlers map[string]*registry.Handler

	servers []*http.Server
}

// StartStack starts one server per checked-in registry fixture set.
func StartStack() (*Stack, error) {
	ids, err := fixtures.RegistrySetIDs()
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	boundary, err := fixtures.ReceiptBoundary()
	if err != nil {
		return nil, err
	}

	stack := &Stack{
		Endpoints: make(map[string]string, len(ids)),
		Handlers:  make(map[string]*registry.Handler, len(ids)),
	}
	for _, id := range ids {
		set, err := fixtures.RegistrySet(id)
		if err != nil {
			stack.Close()
			return nil, err
		}
		checkedInURL, err := fixtures.RegistryURL(id)
		if err != nil {
			stack.Close()
			return nil, err
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			stack.Close()
			return nil, err
		}
		handler := registry.NewHandler(set, boundary)
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}()
		stack.servers = append(stack.servers, server)
		stack.Handlers[id] = handler
		stack.Endpoints[checkedInURL] = fmt.Sprintf("http://%s", listener.Addr().String())
	}
	return stack, nil
}

// Requests returns the requests one registry observed.
func (s *Stack) Requests(registryID string) []registry.Request {
	handler, ok := s.Handlers[registryID]
	if !ok {
		return nil
	}
	return handler.Requests()
}

// ResetRequests clears every registry's observations.
func (s *Stack) ResetRequests() {
	for _, handler := range s.Handlers {
		handler.Reset()
	}
}

// Close stops every server.
func (s *Stack) Close() {
	for _, server := range s.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = server.Shutdown(ctx)
		cancel()
	}
	s.servers = nil
}
