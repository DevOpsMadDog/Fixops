/**
 * SupportPage
 * Route: /support
 * API: POST /api/v1/support/ticket
 *
 * Features:
 *  - Contact form: name, email, subject, description
 *  - Submit support ticket → notification_engine sends email to support@aldeci
 *  - Success toast on submission
 *  - Dark mode support
 */

import { useState } from "react";
import { Mail, Send, CheckCircle, AlertCircle } from "lucide-react";
import api from "@/lib/api";

interface SupportForm {
  name: string;
  email: string;
  subject: string;
  description: string;
}

export default function SupportPage() {
  const [form, setForm] = useState<SupportForm>({
    name: "",
    email: "",
    subject: "",
    description: "",
  });
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<"idle" | "success" | "error">("idle");
  const [errorMsg, setErrorMsg] = useState("");

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setStatus("idle");
    setErrorMsg("");

    try {
      const response = await api.post("/api/v1/support/ticket", form);
      if (response.status === 200 || response.status === 201) {
        setStatus("success");
        setForm({ name: "", email: "", subject: "", description: "" });
        setTimeout(() => setStatus("idle"), 5000);
      }
    } catch (err: any) {
      setStatus("error");
      setErrorMsg(
        err.response?.data?.message ||
          err.message ||
          "Failed to submit support ticket"
      );
      setTimeout(() => setStatus("idle"), 5000);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-50 p-8">
      <div className="max-w-2xl mx-auto">
        {/* Header */}
        <div className="mb-12">
          <div className="flex items-center gap-3 mb-4">
            <Mail className="w-8 h-8 text-indigo-400" />
            <h1 className="text-3xl font-bold">Support</h1>
          </div>
          <p className="text-slate-400">
            Have a question or issue? Submit a support ticket and our team will
            get back to you as soon as possible.
          </p>
        </div>

        {/* Status Messages */}
        {status === "success" && (
          <div className="mb-6 p-4 bg-emerald-500/15 border border-emerald-500/30 rounded-lg flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-emerald-400 mt-0.5 flex-shrink-0" />
            <div>
              <p className="font-semibold text-emerald-400">
                Support ticket submitted
              </p>
              <p className="text-emerald-300 text-sm">
                We've received your message and will respond within 24 hours.
              </p>
            </div>
          </div>
        )}

        {status === "error" && (
          <div className="mb-6 p-4 bg-red-500/15 border border-red-500/30 rounded-lg flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
            <div>
              <p className="font-semibold text-red-400">Submission failed</p>
              <p className="text-red-300 text-sm">{errorMsg}</p>
            </div>
          </div>
        )}

        {/* Form */}
        <form
          onSubmit={handleSubmit}
          className="bg-slate-800 border border-slate-700 rounded-lg p-8 space-y-6"
        >
          {/* Name */}
          <div>
            <label className="block text-sm font-semibold mb-2 text-slate-200">
              Full Name
            </label>
            <input
              type="text"
              name="name"
              value={form.name}
              onChange={handleChange}
              required
              className="w-full px-4 py-2.5 bg-slate-900 border border-slate-600 rounded-lg text-slate-50 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
              placeholder="John Doe"
            />
          </div>

          {/* Email */}
          <div>
            <label className="block text-sm font-semibold mb-2 text-slate-200">
              Email Address
            </label>
            <input
              type="email"
              name="email"
              value={form.email}
              onChange={handleChange}
              required
              className="w-full px-4 py-2.5 bg-slate-900 border border-slate-600 rounded-lg text-slate-50 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
              placeholder="john@example.com"
            />
          </div>

          {/* Subject */}
          <div>
            <label className="block text-sm font-semibold mb-2 text-slate-200">
              Subject
            </label>
            <input
              type="text"
              name="subject"
              value={form.subject}
              onChange={handleChange}
              required
              className="w-full px-4 py-2.5 bg-slate-900 border border-slate-600 rounded-lg text-slate-50 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
              placeholder="How can we help?"
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm font-semibold mb-2 text-slate-200">
              Message
            </label>
            <textarea
              name="description"
              value={form.description}
              onChange={handleChange}
              required
              rows={6}
              className="w-full px-4 py-2.5 bg-slate-900 border border-slate-600 rounded-lg text-slate-50 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 resize-none"
              placeholder="Please describe your issue in detail..."
            />
          </div>

          {/* Submit Button */}
          <div className="flex justify-end gap-3 pt-4">
            <button
              type="reset"
              onClick={() => setForm({ name: "", email: "", subject: "", description: "" })}
              className="px-6 py-2.5 bg-slate-700 hover:bg-slate-600 text-slate-50 rounded-lg font-medium transition-colors"
            >
              Clear
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-700 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors flex items-center gap-2"
            >
              <Send className="w-4 h-4" />
              {loading ? "Submitting..." : "Submit"}
            </button>
          </div>
        </form>

        {/* Footer Note */}
        <div className="mt-12 p-6 bg-slate-800/50 border border-slate-700 rounded-lg">
          <p className="text-slate-400 text-sm">
            <strong>Response time:</strong> Our support team typically responds
            within 24 hours during business hours. For urgent issues, please
            contact sales@aldeci.com.
          </p>
        </div>
      </div>
    </div>
  );
}
