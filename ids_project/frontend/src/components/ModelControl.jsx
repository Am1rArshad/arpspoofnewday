import React, { useEffect, useState } from "react";
import { BrainCircuit, Loader2, RefreshCw, Trash2 } from "lucide-react";
import { api } from "../api";

export default function ModelControl() {
  const [status, setStatus] = useState(null);
  const [retraining, setRetraining] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteText, setDeleteText] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [message, setMessage] = useState("");

  const loadStatus = () => api.modelStatus().then(setStatus).catch((error) => setMessage(error.message));

  useEffect(() => {
    loadStatus();
    const interval = setInterval(loadStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleRetrain = async () => {
    setMessage("");
    setRetraining(true);
    try {
      await api.retrainModel();
      const poll = setInterval(async () => {
        const nextStatus = await api.modelStatus();
        setStatus(nextStatus);
        if (!nextStatus.is_retraining) {
          clearInterval(poll);
          setRetraining(false);
        }
      }, 2000);
    } catch (error) {
      setRetraining(false);
      setMessage(error.message);
    }
  };

  const handleDelete = async () => {
    if (deleteText !== "DELETE") return;
    setDeleting(true);
    setMessage("");
    try {
      await api.deleteModelTrainingData();
      setConfirmDelete(false);
      setDeleteText("");
      await loadStatus();
      setMessage("Model and all training data deleted.");
    } catch (error) {
      setMessage(error.message);
    } finally {
      setDeleting(false);
    }
  };

  const formatBytes = (bytes = 0) => `${(bytes / 1024).toFixed(1)} KB`;
  const statusLabel = status?.is_retraining ? "Retraining" : status?.model_loaded ? "Ready" : "Not trained";

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Model Control</h2>
          <p className="text-sm text-slate-500">Manage the XGBoost detection model and its training data.</p>
        </div>
        <button onClick={loadStatus} title="Refresh model status" className="p-2 bg-slate-800 hover:bg-slate-700 rounded-lg">
          <RefreshCw size={16} />
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-500">Model status</p>
          <p className={`mt-1 text-xl font-semibold ${status?.model_loaded ? "text-green-400" : "text-orange-400"}`}>
            {statusLabel}
          </p>
          <p className="text-xs text-slate-500 mt-1">
            Medium: {status?.threshold_low ?? 0.4} / High: {status?.threshold_high ?? 0.7}
          </p>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-500">Training samples</p>
          <p className="mt-1 text-xl font-semibold">{status?.training_samples ?? 0}</p>
          <p className="text-xs text-slate-500 mt-1">Feedback: {status?.feedback_samples ?? 0}</p>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-500">Saved model</p>
          <p className="mt-1 text-xl font-semibold">{status?.model_file_exists ? formatBytes(status.model_file_size_bytes) : "Missing"}</p>
          <p className="text-xs text-slate-500 mt-1">Features: {status?.feature_count ?? 0}</p>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
        <div className="flex items-center gap-3">
          <BrainCircuit className="text-red-400" size={22} />
          <div>
            <h3 className="text-sm font-medium">Training data detail</h3>
            <p className="text-xs text-slate-500">Bootstrap data is generated from captured ARP rule results.</p>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
          <div className="bg-slate-800/60 rounded-lg p-3"><p className="text-xs text-slate-500">Bootstrap total</p><p className="font-semibold">{status?.bootstrap_samples ?? 0}</p></div>
          <div className="bg-slate-800/60 rounded-lg p-3"><p className="text-xs text-slate-500">Positive labels</p><p className="font-semibold text-red-400">{status?.bootstrap_positive_samples ?? 0}</p></div>
          <div className="bg-slate-800/60 rounded-lg p-3"><p className="text-xs text-slate-500">Negative labels</p><p className="font-semibold text-green-400">{status?.bootstrap_negative_samples ?? 0}</p></div>
          <div className="bg-slate-800/60 rounded-lg p-3"><p className="text-xs text-slate-500">Last trained</p><p className="font-semibold text-xs">{status?.last_trained_at ? new Date(status.last_trained_at * 1000).toLocaleString() : "Never"}</p></div>
        </div>
        {message && <p className="text-sm text-slate-300">{message}</p>}
        <div className="flex flex-wrap items-center gap-2">
          <button onClick={handleRetrain} disabled={retraining || deleting || status?.is_retraining} className="flex items-center gap-2 bg-red-600 hover:bg-red-500 disabled:opacity-50 px-4 py-2 rounded-lg text-sm font-medium">
            {retraining || status?.is_retraining ? <Loader2 size={16} className="animate-spin" /> : <BrainCircuit size={16} />}
            {retraining || status?.is_retraining ? "Retraining..." : "Retrain Model with Feedback"}
          </button>
          {!confirmDelete ? (
            <button onClick={() => setConfirmDelete(true)} disabled={retraining || status?.is_retraining} className="flex items-center gap-2 text-sm bg-slate-800 hover:bg-red-600/30 text-red-400 disabled:opacity-50 px-3 py-2 rounded-lg">
              <Trash2 size={14} /> Delete ML Training
            </button>
          ) : (
            <div className="flex flex-wrap items-center gap-2 bg-red-500/10 border border-red-500/30 rounded-lg p-2">
              <span className="text-xs text-red-300">Type DELETE to remove the model, bootstrap data, and feedback.</span>
              <input value={deleteText} onChange={(event) => setDeleteText(event.target.value)} placeholder="DELETE" className="w-24 bg-slate-900 border border-red-500/30 rounded px-2 py-1 text-xs" />
              <button onClick={handleDelete} disabled={deleting || deleteText !== "DELETE"} className="text-red-300 text-sm font-medium disabled:opacity-40">{deleting ? "Deleting..." : "Confirm"}</button>
              <button onClick={() => { setConfirmDelete(false); setDeleteText(""); }} className="text-slate-400 text-sm">Cancel</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}