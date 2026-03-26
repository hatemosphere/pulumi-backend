package main

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/hatemosphere/pulumi-backend/internal/config"
)

// --- Tracing ---

func initializeTracer(ctx context.Context, cfg *config.Config) (*sdktrace.TracerProvider, error) {
	if cfg.OTelServiceName == "" {
		return nil, nil
	}

	tp, err := initTracer(ctx, cfg.OTelServiceName)
	if err != nil {
		return nil, fmt.Errorf("initialize OpenTelemetry: %w", err)
	}

	slog.Info("OpenTelemetry tracing enabled", "service", cfg.OTelServiceName)
	return tp, nil
}

func initTracer(ctx context.Context, serviceName string) (*sdktrace.TracerProvider, error) {
	exporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create OTLP exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
		)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp, nil
}
