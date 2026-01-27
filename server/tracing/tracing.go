package tracing

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// SetupLangWatch initializes the LangWatch OpenTelemetry exporter
func SetupLangWatch(apiKey string, endpoint string) func() {
	ctx := context.Background()

	options := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(endpoint),
		otlptracehttp.WithHeaders(map[string]string{
			"Authorization": "Bearer " + apiKey,
		}),
	}

	exporter, err := otlptracehttp.New(ctx, options...)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create LangWatch OTLP exporter")
		return func() {}
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(tp)

	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tp.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Error shutting down LangWatch tracer provider")
		}
	}
}
