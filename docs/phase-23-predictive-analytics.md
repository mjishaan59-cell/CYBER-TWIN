# Phase 23: Predictive Analytics & Resource Forecasting Subsystem

## Overview
Phase 23 implements a Machine Learning and statistical Predictive Analytics Subsystem for Linux infrastructure. It continuously evaluates historical operating system metrics (CPU, Memory, Disk, and Network telemetry) to project future utilization trajectories, estimate time-to-exhaustion for storage partitions, compute anomaly trend probabilities, and emit proactive saturation alerts before resource exhaustion degrades system stability.

---

## Key Capabilities

1. **Machine Learning Forecasting Engine**:
   - **Ridge Trend Extrapolation**: Regularized linear and polynomial models capable of filtering high-frequency noise from system metrics while capturing multi-horizon trends (+15m, +1h, +6h).
   - **Statistical Drift Baseline Fallback**: Handles fresh node enrollments or insufficient historical data (<5 samples) gracefully by projecting bounded statistical drift.
   - **Dynamic Confidence Intervals**: Computes 95% upper and lower prediction bands ($[-1.96\sigma, +1.96\sigma]$) that expand proportionally over longer time horizons.

2. **Multi-Resource Forecasting**:
   - **CPU Usage Forecast**: Projects short-term spikes (+15m) and sustained overload (+1h).
   - **Memory Usage & Leak Detection**: Monitors rate of change (%/hour) to detect insidious memory leaks and daemon bloat.
   - **Storage Time-to-Exhaustion**: Calculates the precise number of hours until disk utilization reaches the 95% critical threshold based on empirical fill rate.
   - **Network Traffic Projections**: Models throughput demands correlated with compute and memory activity.

3. **Anomaly Trend Likelihood Prediction**:
   - Evaluates multi-metric volatility, rising resource slopes, and capacity pressures to estimate the probability (0-100%) of entering an anomalous or degraded state in the upcoming 1-hour window.
   - Classifications: `NOMINAL_STABILITY`, `ELEVATED_ANOMALY_RISK`, `CRITICAL_ANOMALY_LIKELY`.

4. **Proactive Saturation & Capacity Alerts**:
   - Automatically triggers alerts *in advance* of failure:
     - `PREDICTED_CPU_SATURATION`: Emitted when projected 15-minute CPU exceeds 88%.
     - `SUSPECTED_MEMORY_LEAK`: Emitted when memory consumption grows at >2.0%/hour continuously.
     - `PROJECTED_DISK_EXHAUSTION`: Emitted when disk capacity is projected to reach 95% within 48 hours.

5. **Web Dashboard Integration**:
   - Live forecasting KPI cards displaying projected values, trend direction arrows (↑, ↓, →), and rate of change.
   - Countdown timer for storage exhaustion.
   - Dynamic Chart.js forecasting canvas displaying historical telemetry, dotted forward projections, and shaded 95% confidence intervals.

---

## API Reference

### 1. Host Forecast Summary
```bash
curl -H "Authorization: Bearer <TOKEN>" \
  "http://localhost:8000/predictive-analytics/forecast?hostname=prac-server"
```
**Example Response:**
```json
{
  "hostname": "prac-server",
  "generated_at": "2026-11-10T10:20:00Z",
  "cpu": {
    "current_value": 32.4,
    "predicted_15m": 35.8,
    "predicted_1h": 41.2,
    "trend_direction": "RISING",
    "rate_per_hour": 8.8,
    "confidence_pct": 91.5
  },
  "disk": {
    "current_value": 68.2,
    "time_to_exhaustion_hours": 142.5,
    "rate_per_hour": 0.18
  },
  "anomaly_trend": {
    "probability_pct": 28.5,
    "status": "NOMINAL_STABILITY",
    "summary": "Calculated 28.5% probability of operational anomaly over next 1 hour."
  },
  "predictive_alerts": []
}
```

### 2. Time-to-Exhaustion Endpoint
```bash
curl -H "Authorization: Bearer <TOKEN>" \
  "http://localhost:8000/predictive-analytics/exhaustion?hostname=prac-server"
```

### 3. Metric-Specific Projection with Upper/Lower Bounds
```bash
curl -H "Authorization: Bearer <TOKEN>" \
  "http://localhost:8000/predictive-analytics/metrics/cpu?hostname=prac-server"
```

### 4. Trigger Model Retraining
```bash
curl -X POST -H "Authorization: Bearer <TOKEN>" \
  "http://localhost:8000/predictive-analytics/retrain?hostname=prac-server"
```

---

## Verification & Testing
Covered by `tests/test_phase23_predictive_analytics.py`:
- Polynomial and Ridge trend fitting verification.
- Confidence interval bounds consistency (`lower <= pred <= upper`).
- Zero-data and low-data fallback stability.
- Storage exhaustion countdown formulas.
- Proactive alert triggers and REST endpoints.
