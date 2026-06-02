import { jsPDF } from 'jspdf'
import type { IntelligenceReport } from './types'

export function downloadSecurityReport(report: IntelligenceReport, title = 'Security Intelligence Report') {
  const doc = new jsPDF()
  const margin = 14
  let y = 20
  const p = report.platform

  const line = (text: string, size = 10, bold = false) => {
    doc.setFontSize(size)
    doc.setFont('helvetica', bold ? 'bold' : 'normal')
    const lines = doc.splitTextToSize(text, 180)
    if (y + lines.length * 6 > 280) {
      doc.addPage()
      y = 20
    }
    doc.text(lines, margin, y)
    y += lines.length * 6 + 2
  }

  line('AEGIS-X Security Intelligence Report', 16, true)
  line(title, 12, true)
  line(`Target: ${report.targetTitle ?? ''} ${report.targetUrl ?? ''}`, 9)
  line(`Generated: ${new Date(report.generatedAt).toLocaleString()}`, 9)
  y += 4

  line('Executive Summary', 12, true)
  line(report.executiveV2.overallPosture)
  line(`Top Risk: ${report.executiveV2.topRisk}`)
  line(`Priority Fix: ${report.executiveV2.priorityFix}`)
  y += 2

  line(`Observed Posture: ${p.observedPosture.label}`, 11, true)
  line(p.observedPosture.summary)
  line(`Evidence Coverage: ${p.evidenceCoverage.percent}% · Assessment Confidence: ${p.assessmentConfidence.percent}%`)
  line(p.assessmentConfidence.reason)
  line(`Risk Score (coverage-adjusted): ${p.riskScore}/100 (Grade ${report.grade})`, 11, true)
  y += 2

  line('Top Attack Paths', 12, true)
  p.topAttackPaths.slice(0, 5).forEach((path) => {
    line(`${path.name}: ${path.steps.join(' → ')}`)
    line(`Likelihood ${path.likelihood} · Impact ${path.impact} · Confidence ${path.confidence}%`)
  })
  y += 2

  line('Remediation Roadmap', 12, true)
  p.remediationRoadmap.slice(0, 8).forEach((r) => {
    line(`P${r.priority}: ${r.fix} (${r.effort}, −${r.riskReductionPercent}% risk)`)
  })
  y += 2

  line('Findings (Evidence)', 12, true)
  p.findings.slice(0, 15).forEach((f) => {
    line(`[${f.severity}] ${f.title} (${f.confidenceLevel})`, 10, true)
    line(`Evidence: ${f.evidence}`)
    line(`Observed: ${f.observedSignal}`)
    line(`Fix: ${f.recommendedFix}`)
    y += 1
  })

  line('MITRE ATT&CK (sample)', 12, true)
  p.mitreMapping.slice(0, 8).forEach((m) => line(`${m.tactic} · ${m.technique} (${m.confidence}%)`))

  doc.save(`aegis-intelligence-${Date.now()}.pdf`)
}
