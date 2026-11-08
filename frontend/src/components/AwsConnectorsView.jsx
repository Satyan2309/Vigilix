import React, { useState } from "react";
import { 
  Cloud, 
  ShieldCheck, 
  AlertTriangle, 
  RefreshCw, 
  Database, 
  Radio, 
  CheckCircle2, 
  ExternalLink,
  Lock,
  Layers,
  Archive,
  Cpu
} from "lucide-react";
import { 
  getAwsStatus, 
  syncCloudTrail, 
  syncCloudTrailS3, 
  syncGuardDuty, 
  syncSecurityHub 
} from "../api";

export default function AwsConnectorsView({ onSyncComplete }) {
  const [region, setRegion] = useState("ap-south-1");
  const [profile, setProfile] = useState("");
  const [checkingStatus, setCheckingStatus] = useState(false);
  const [awsStatus, setAwsStatus] = useState(null);
  const [statusError, setStatusError] = useState("");

  // CloudTrail form
  const [ctHours, setCtHours] = useState(24);
  const [ctLimit, setCtLimit] = useState(200);
  const [syncingCt, setSyncingCt] = useState(false);

  // S3 form
  const [s3Bucket, setS3Bucket] = useState("");
  const [s3Prefix, setS3Prefix] = useState("AWSLogs/");
  const [s3Hours, setS3Hours] = useState(24);
  const [s3MaxObjects, setS3MaxObjects] = useState(20);
  const [syncingS3, setSyncingS3] = useState(false);

  // GuardDuty / SecurityHub
  const [syncingGd, setSyncingGd] = useState(false);
  const [syncingSh, setSyncingSh] = useState(false);

  // Result messages
  const [syncResult, setSyncResult] = useState(null);

  const handleCheckStatus = async () => {
    setCheckingStatus(true);
    setStatusError("");
    setAwsStatus(null);
    try {
      const res = await getAwsStatus(region, profile);
      setAwsStatus(res);
    } catch (err) {
      setStatusError(err.message || "Failed to query AWS status. Ensure AWS credentials exist.");
    } finally {
      setCheckingStatus(false);
    }
  };

  const handleSyncCloudTrail = async () => {
    setSyncingCt(true);
    setSyncResult(null);
    try {
      const res = await syncCloudTrail(region, ctHours, ctLimit, profile);
      setSyncResult({
        type: "success",
        title: "CloudTrail Direct Ingestion Completed",
        details: `Fetched ${res.fetched_events || 0} events (${res.new_events || 0} newly saved) from AWS CloudTrail [${res.region}]. Total store: ${res.total_events}.`
      });
      onSyncComplete?.();
    } catch (err) {
      setSyncResult({
        type: "error",
        title: "CloudTrail Sync Failed",
        details: err.message || "AWS API call failed. Verify IAM credentials."
      });
    } finally {
      setSyncingCt(false);
    }
  };

  const handleSyncS3 = async () => {
    if (!s3Bucket.trim()) {
      setSyncResult({ type: "error", title: "Bucket Required", details: "Please specify an S3 bucket name containing CloudTrail logs." });
      return;
    }
    setSyncingS3(true);
    setSyncResult(null);
    try {
      const res = await syncCloudTrailS3(s3Bucket, s3Prefix, region, s3Hours, s3MaxObjects, profile);
      setSyncResult({
        type: "success",
        title: "S3 CloudTrail Archive Parsed",
        details: `Extracted ${res.fetched_events || 0} events (${res.new_events || 0} saved) from s3://${res.bucket}/${res.prefix}. Total store: ${res.total_events}.`
      });
      onSyncComplete?.();
    } catch (err) {
      setSyncResult({
        type: "error",
        title: "S3 Sync Failed",
        details: err.message || "Unable to read S3 bucket. Verify s3:GetObject and s3:ListBucket IAM permissions."
      });
    } finally {
      setSyncingS3(false);
    }
  };

  const handleSyncGuardDuty = async () => {
    setSyncingGd(true);
    setSyncResult(null);
    try {
      const res = await syncGuardDuty(region, 50, profile);
      setSyncResult({
        type: "success",
        title: "GuardDuty Findings Ingested",
        details: `Pulled ${res.fetched_findings || 0} findings (${res.new_events || 0} newly saved) into telemetry events.`
      });
      onSyncComplete?.();
    } catch (err) {
      setSyncResult({
        type: "error",
        title: "GuardDuty Sync Failed",
        details: err.message || "Could not fetch GuardDuty findings. Ensure GuardDuty detector is active."
      });
    } finally {
      setSyncingGd(false);
    }
  };

  const handleSyncSecurityHub = async () => {
    setSyncingSh(true);
    setSyncResult(null);
    try {
      const res = await syncSecurityHub(region, 100, profile);
      setSyncResult({
        type: "success",
        title: "Security Hub Findings Ingested",
        details: `Retrieved ${res.fetched_findings || 0} findings (${res.new_events || 0} saved) from AWS Security Hub.`
      });
      onSyncComplete?.();
    } catch (err) {
      setSyncResult({
        type: "error",
        title: "Security Hub Sync Failed",
        details: err.message || "Could not fetch Security Hub findings. Verify Security Hub enablement."
      });
    } finally {
      setSyncingSh(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Top Banner */}
      <div className="card" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <h2 style={{ fontSize: "1.25rem", fontWeight: 700, display: "flex", alignItems: "center", gap: "8px", margin: 0 }}>
            <Cloud size={20} color="var(--primary)" />
            AWS Live Ingestion & Telemetry Connectors
          </h2>
          <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", margin: "4px 0 0 0" }}>
            Ingest live AWS CloudTrail audit records, compressed S3 log archives, and automated GuardDuty & Security Hub alerts directly into your PostgreSQL SOC database.
          </p>
        </div>

        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <span className="badge badge-info" style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <Radio size={12} className="pulse" />
            Boto3 AWS SDK
          </span>
          <span className="badge badge-low">Live Ingestion</span>
        </div>
      </div>

      {/* Sync Result Alert */}
      {syncResult && (
        <div 
          className="card" 
          style={{ 
            borderColor: syncResult.type === "success" ? "rgba(16, 185, 129, 0.4)" : "rgba(239, 68, 68, 0.4)",
            background: syncResult.type === "success" ? "rgba(16, 185, 129, 0.08)" : "rgba(239, 68, 68, 0.08)",
            padding: "16px 20px"
          }}
        >
          <div style={{ display: "flex", alignItems: "flex-start", gap: "12px" }}>
            {syncResult.type === "success" ? (
              <CheckCircle2 size={20} color="var(--low)" style={{ flexShrink: 0, marginTop: "2px" }} />
            ) : (
              <AlertTriangle size={20} color="var(--critical)" style={{ flexShrink: 0, marginTop: "2px" }} />
            )}
            <div>
              <div style={{ fontWeight: 600, color: syncResult.type === "success" ? "var(--low)" : "var(--critical)", fontSize: "0.95rem" }}>
                {syncResult.title}
              </div>
              <div style={{ color: "var(--text-secondary)", fontSize: "0.85rem", marginTop: "4px" }}>
                {syncResult.details}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Connection & Auth Health Checker */}
      <div className="card">
        <h3 style={{ fontSize: "1rem", fontWeight: 700, margin: "0 0 16px 0", display: "flex", alignItems: "center", gap: "8px" }}>
          <ShieldCheck size={18} color="var(--primary)" />
          AWS IAM Credentials & Connectivity Probe
        </h3>
        
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "16px", marginBottom: "16px" }}>
          <div>
            <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "6px", textTransform: "uppercase" }}>
              AWS Region
            </label>
            <select 
              className="input-control" 
              value={region} 
              onChange={(e) => setRegion(e.target.value)}
            >
              <option value="ap-south-1">ap-south-1 (Mumbai)</option>
              <option value="us-east-1">us-east-1 (N. Virginia)</option>
              <option value="us-east-2">us-east-2 (Ohio)</option>
              <option value="us-west-2">us-west-2 (Oregon)</option>
              <option value="eu-west-1">eu-west-1 (Ireland)</option>
              <option value="eu-central-1">eu-central-1 (Frankfurt)</option>
              <option value="ap-southeast-1">ap-southeast-1 (Singapore)</option>
            </select>
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "6px", textTransform: "uppercase" }}>
              AWS Profile (Optional)
            </label>
            <input 
              type="text" 
              className="input-control" 
              placeholder="e.g. default or production"
              value={profile} 
              onChange={(e) => setProfile(e.target.value)}
            />
          </div>

          <div style={{ display: "flex", alignItems: "flex-end" }}>
            <button 
              className="btn btn-primary" 
              style={{ width: "100%" }}
              onClick={handleCheckStatus}
              disabled={checkingStatus}
            >
              <RefreshCw size={14} className={checkingStatus ? "spin" : ""} />
              {checkingStatus ? "Verifying STS..." : "Probe AWS Credentials"}
            </button>
          </div>
        </div>

        {statusError && (
          <div style={{ padding: "12px", background: "rgba(239, 68, 68, 0.1)", borderRadius: "8px", border: "1px solid rgba(239,68,68,0.2)", fontSize: "0.85rem", color: "var(--critical)" }}>
            <AlertTriangle size={14} style={{ display: "inline", verticalAlign: "middle", marginRight: "6px" }} />
            {statusError}
          </div>
        )}

        {awsStatus && (
          <div style={{ 
            marginTop: "16px", 
            padding: "16px", 
            background: "rgba(0,0,0,0.3)", 
            borderRadius: "8px", 
            border: "1px solid var(--border)",
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
            gap: "12px"
          }}>
            <div>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>AWS Account ID</div>
              <div style={{ fontFamily: "var(--font-mono)", fontWeight: 600, color: "var(--primary)" }}>
                {awsStatus.account || "N/A"}
              </div>
            </div>
            <div>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>IAM Identity ARN</div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--text-secondary)", wordBreak: "break-all" }}>
                {awsStatus.arn || "N/A"}
              </div>
            </div>
            <div>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Region & STS Status</div>
              <div style={{ display: "flex", gap: "6px", marginTop: "4px" }}>
                <span className="badge badge-low">{awsStatus.region}</span>
                <span className="badge badge-info">AUTHENTICATED</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Ingestion Modules Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))", gap: "20px" }}>
        {/* Module 1: CloudTrail Direct Sync */}
        <div className="card" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
              <h3 style={{ fontSize: "0.95rem", fontWeight: 700, margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
                <Layers size={16} color="var(--primary)" />
                AWS CloudTrail Live API Events
              </h3>
              <span className="badge badge-info">Realtime</span>
            </div>
            <p style={{ fontSize: "0.82rem", color: "var(--text-muted)", marginBottom: "16px" }}>
              Queries the AWS CloudTrail lookup events API for management operations, root logins, unauthorized API calls, and security group alterations.
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "16px" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "4px" }}>
                  Lookback Window ({ctHours}h)
                </label>
                <input 
                  type="range" 
                  min="1" 
                  max="168" 
                  value={ctHours} 
                  onChange={(e) => setCtHours(Number(e.target.value))}
                  style={{ width: "100%" }}
                />
              </div>
              <div>
                <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "4px" }}>
                  Max Event Limit
                </label>
                <select 
                  className="input-control" 
                  value={ctLimit} 
                  onChange={(e) => setCtLimit(Number(e.target.value))}
                >
                  <option value={50}>50 events</option>
                  <option value={100}>100 events</option>
                  <option value={200}>200 events</option>
                  <option value={500}>500 events</option>
                </select>
              </div>
            </div>
          </div>

          <button 
            className="btn btn-primary" 
            onClick={handleSyncCloudTrail} 
            disabled={syncingCt}
            style={{ width: "100%", justifyContent: "center" }}
          >
            <RefreshCw size={14} className={syncingCt ? "spin" : ""} />
            {syncingCt ? "Querying CloudTrail Events..." : `Ingest Last ${ctHours}h CloudTrail Events`}
          </button>
        </div>

        {/* Module 2: S3 CloudTrail Bucket Ingestion */}
        <div className="card" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
              <h3 style={{ fontSize: "0.95rem", fontWeight: 700, margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
                <Archive size={16} color="var(--medium)" />
                S3 CloudTrail Log Archive Sync
              </h3>
              <span className="badge badge-medium">gzip .json.gz</span>
            </div>
            <p style={{ fontSize: "0.82rem", color: "var(--text-muted)", marginBottom: "16px" }}>
              Streams, decompresses, and normalizes multi-account audit logs stored in Amazon S3 buckets.
            </p>

            <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginBottom: "16px" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "4px" }}>
                  S3 Bucket Name *
                </label>
                <input 
                  type="text" 
                  className="input-control" 
                  placeholder="e.g. my-org-cloudtrail-audit-logs"
                  value={s3Bucket} 
                  onChange={(e) => setS3Bucket(e.target.value)}
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "4px" }}>
                    S3 Prefix
                  </label>
                  <input 
                    type="text" 
                    className="input-control" 
                    value={s3Prefix} 
                    onChange={(e) => setS3Prefix(e.target.value)}
                  />
                </div>
                <div>
                  <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "4px" }}>
                    Max S3 Objects ({s3MaxObjects})
                  </label>
                  <input 
                    type="range" 
                    min="5" 
                    max="100" 
                    value={s3MaxObjects} 
                    onChange={(e) => setS3MaxObjects(Number(e.target.value))}
                    style={{ width: "100%" }}
                  />
                </div>
              </div>
            </div>
          </div>

          <button 
            className="btn btn-secondary" 
            onClick={handleSyncS3} 
            disabled={syncingS3}
            style={{ width: "100%", justifyContent: "center" }}
          >
            <Database size={14} className={syncingS3 ? "spin" : ""} />
            {syncingS3 ? "Streaming & Decompressing..." : "Sync S3 Log Archive"}
          </button>
        </div>

        {/* Module 3: GuardDuty Security Connector */}
        <div className="card" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
              <h3 style={{ fontSize: "0.95rem", fontWeight: 700, margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
                <Cpu size={16} color="var(--critical)" />
                Amazon GuardDuty Telemetry
              </h3>
              <span className="badge badge-critical">Threat Intel</span>
            </div>
            <p style={{ fontSize: "0.82rem", color: "var(--text-muted)", marginBottom: "16px" }}>
              Pulls active GuardDuty threat detection findings including EC2 cryptomining alerts, brute force attempts, and anomalous IAM token creation.
            </p>
          </div>

          <button 
            className="btn btn-secondary" 
            onClick={handleSyncGuardDuty} 
            disabled={syncingGd}
            style={{ width: "100%", justifyContent: "center", borderColor: "rgba(239, 68, 68, 0.4)" }}
          >
            <ShieldCheck size={14} className={syncingGd ? "spin" : ""} color="var(--critical)" />
            {syncingGd ? "Fetching GuardDuty Findings..." : "Ingest GuardDuty Findings"}
          </button>
        </div>

        {/* Module 4: AWS Security Hub Findings */}
        <div className="card" style={{ display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
              <h3 style={{ fontSize: "0.95rem", fontWeight: 700, margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
                <ShieldCheck size={16} color="var(--high)" />
                AWS Security Hub Posture
              </h3>
              <span className="badge badge-high">Compliance</span>
            </div>
            <p style={{ fontSize: "0.82rem", color: "var(--text-muted)", marginBottom: "16px" }}>
              Ingests CIS AWS Foundations benchmark violations, AWS Foundational Security Best Practice alerts, and multi-service compliance findings.
            </p>
          </div>

          <button 
            className="btn btn-secondary" 
            onClick={handleSyncSecurityHub} 
            disabled={syncingSh}
            style={{ width: "100%", justifyContent: "center", borderColor: "rgba(249, 115, 22, 0.4)" }}
          >
            <Radio size={14} className={syncingSh ? "spin" : ""} color="var(--high)" />
            {syncingSh ? "Querying Security Hub..." : "Ingest Security Hub Findings"}
          </button>
        </div>
      </div>
    </div>
  );
}
