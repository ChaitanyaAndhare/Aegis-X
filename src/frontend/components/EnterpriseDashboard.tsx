/**
 * Task 5: Enterprise UX Dashboard
 * Ultra-clean, minimalist, high-density dashboard with Executive/Technical view toggle
 */

import React, { useState } from 'react';
import { Shield, Activity, AlertTriangle, CheckCircle, XCircle, Database, Globe, Cookie, Lock } from 'lucide-react';
import { ScanResult, SecurityFinding, Severity } from '../backend/core/types';

type ViewMode = 'executive' | 'technical';

interface EnterpriseDashboardProps {
  scanResult: ScanResult | null;
  onScanComplete?: (result: ScanResult) => void;
}

export const EnterpriseDashboard: React.FC<EnterpriseDashboardProps> = ({ scanResult, onScanComplete }) => {
  const [viewMode, setViewMode] = useState<ViewMode>('executive');
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);

  if (!scanResult) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50">
        <div className="text-center">
          <Shield className="w-16 h-16 mx-auto mb-4 text-gray-400" />
          <p className="text-gray-600">No scan results available</p>
        </div>
      </div>
    );
  }

  const { securityDebt, findings, assetInventory, delta } = scanResult;

  const getSeverityColor = (severity: Severity): string => {
    const colors = {
      CRITICAL: 'text-red-600 bg-red-50 border-red-200',
      HIGH: 'text-orange-600 bg-orange-50 border-orange-200',
      MEDIUM: 'text-yellow-600 bg-yellow-50 border-yellow-200',
      LOW: 'text-blue-600 bg-blue-50 border-blue-200',
      INFO: 'text-gray-600 bg-gray-50 border-gray-200'
    };
    return colors[severity];
  };

  const ExecutiveView = () => (
    <div className="space-y-6">
      {/* Security Debt Score */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <Shield className="w-5 h-5" />
          Security Debt Score
        </h2>
        <div className="grid grid-cols-5 gap-4">
          <div className="text-center">
            <div className={`text-4xl font-bold ${securityDebt.totalScore > 75 ? 'text-red-600' : securityDebt.totalScore > 50 ? 'text-orange-600' : 'text-green-600'}`}>
              {securityDebt.totalScore}
            </div>
            <div className="text-sm text-gray-600 mt-1">Total Score</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-red-600">{securityDebt.criticalCount}</div>
            <div className="text-sm text-gray-600 mt-1">Critical</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-orange-600">{securityDebt.highCount}</div>
            <div className="text-sm text-gray-600 mt-1">High</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-yellow-600">{securityDebt.mediumCount}</div>
            <div className="text-sm text-gray-600 mt-1">Medium</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-blue-600">{securityDebt.lowCount}</div>
            <div className="text-sm text-gray-600 mt-1">Low</div>
          </div>
        </div>
        <div className="mt-4 flex items-center gap-2">
          {securityDebt.trend === 'improving' && <CheckCircle className="w-5 h-5 text-green-600" />}
          {securityDebt.trend === 'degrading' && <XCircle className="w-5 h-5 text-red-600" />}
          {securityDebt.trend === 'stable' && <Activity className="w-5 h-5 text-gray-600" />}
          <span className="text-sm text-gray-600 capitalize">Trend: {securityDebt.trend}</span>
        </div>
      </div>

      {/* Business Risk Panel */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <AlertTriangle className="w-5 h-5" />
          Business Risk & Compliance
        </h2>
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <h3 className="text-sm font-medium text-gray-700">Compliance Status</h3>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">PCI-DSS</span>
                {securityDebt.complianceFlags.pciDss ? (
                  <CheckCircle className="w-4 h-4 text-green-600" />
                ) : (
                  <XCircle className="w-4 h-4 text-red-600" />
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">SOC2</span>
                {securityDebt.complianceFlags.soc2 ? (
                  <CheckCircle className="w-4 h-4 text-green-600" />
                ) : (
                  <XCircle className="w-4 h-4 text-red-600" />
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">GDPR</span>
                {securityDebt.complianceFlags.gdpr ? (
                  <CheckCircle className="w-4 h-4 text-green-600" />
                ) : (
                  <XCircle className="w-4 h-4 text-red-600" />
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">HIPAA</span>
                {securityDebt.complianceFlags.hipaa ? (
                  <CheckCircle className="w-4 h-4 text-green-600" />
                ) : (
                  <XCircle className="w-4 h-4 text-red-600" />
                )}
              </div>
            </div>
          </div>
          <div className="space-y-2">
            <h3 className="text-sm font-medium text-gray-700">Attack Vector Summary</h3>
            <div className="space-y-2 text-sm text-gray-600">
              <div>Target: {assetInventory.targetUrl}</div>
              <div>Organization Type: {assetInventory.orgType}</div>
              <div>Scan Duration: {scanResult.duration}s</div>
              <div>Total Findings: {findings.length}</div>
              {delta && (
                <>
                  <div>New Findings: {delta.newFindings.length}</div>
                  <div>Resolved: {delta.resolvedFindings.length}</div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Actionable Items */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Priority Actions</h2>
        <div className="space-y-3">
          {findings.slice(0, 5).map((finding) => (
            <div
              key={finding.id}
              className={`p-4 rounded-lg border ${getSeverityColor(finding.contextualSeverity)} cursor-pointer hover:opacity-80`}
              onClick={() => {
                setViewMode('technical');
                setSelectedFinding(finding);
              }}
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="font-medium">{finding.title}</div>
                  <div className="text-sm mt-1 opacity-75">{finding.description}</div>
                </div>
                <span className={`text-xs font-semibold px-2 py-1 rounded ${getSeverityColor(finding.contextualSeverity)}`}>
                  {finding.contextualSeverity}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  const TechnicalView = () => (
    <div className="flex gap-6 h-full">
      {/* Asset Surface Navigator */}
      <div className="w-1/3 bg-white rounded-lg shadow-sm border border-gray-200 p-4 overflow-y-auto">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <Globe className="w-5 h-5" />
          Asset Surface
        </h2>
        
        <div className="space-y-4">
          {/* Technologies */}
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-2 flex items-center gap-2">
              <Database className="w-4 h-4" />
              Technologies
            </h3>
            <div className="space-y-1">
              {assetInventory.technologies.map((tech, idx) => (
                <div key={idx} className="text-sm text-gray-600 bg-gray-50 px-3 py-2 rounded">
                  <span className="font-medium">{tech.name}</span>
                  {tech.version && <span className="ml-2 text-gray-400">{tech.version}</span>}
                  <span className="ml-2 text-xs text-gray-400">({tech.category})</span>
                </div>
              ))}
            </div>
          </div>

          {/* Headers */}
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-2 flex items-center gap-2">
              <Lock className="w-4 h-4" />
              Response Headers
            </h3>
            <div className="space-y-1 max-h-48 overflow-y-auto">
              {Object.entries(assetInventory.headers).map(([key, value]) => (
                <div key={key} className="text-xs text-gray-600 bg-gray-50 px-3 py-2 rounded font-mono">
                  <span className="font-semibold">{key}:</span> {value}
                </div>
              ))}
            </div>
          </div>

          {/* Cookies */}
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-2 flex items-center gap-2">
              <Cookie className="w-4 h-4" />
              Cookies
            </h3>
            <div className="space-y-1 max-h-48 overflow-y-auto">
              {assetInventory.cookies.map((cookie, idx) => (
                <div key={idx} className="text-xs text-gray-600 bg-gray-50 px-3 py-2 rounded">
                  <div className="font-semibold">{cookie.name}</div>
                  <div className="flex gap-2 mt-1">
                    {cookie.secure && <span className="text-green-600">Secure</span>}
                    {cookie.httpOnly && <span className="text-blue-600">HttpOnly</span>}
                    {cookie.sameSite && <span className="text-purple-600">{cookie.sameSite}</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Endpoints */}
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-2">Endpoints</h3>
            <div className="space-y-1 max-h-48 overflow-y-auto">
              {assetInventory.endpoints.slice(0, 10).map((endpoint, idx) => (
                <div key={idx} className="text-xs text-gray-600 bg-gray-50 px-3 py-2 rounded font-mono">
                  <span className="font-semibold">{endpoint.method}</span> {endpoint.url}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Evidence Inspector */}
      <div className="w-2/3 bg-white rounded-lg shadow-sm border border-gray-200 p-4 overflow-y-auto">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <Shield className="w-5 h-5" />
          Evidence Inspector
        </h2>

        {selectedFinding ? (
          <div className="space-y-4">
            <div className={`p-4 rounded-lg border ${getSeverityColor(selectedFinding.contextualSeverity)}`}>
              <div className="flex items-start justify-between mb-2">
                <h3 className="text-lg font-semibold">{selectedFinding.title}</h3>
                <span className={`text-sm font-semibold px-3 py-1 rounded ${getSeverityColor(selectedFinding.contextualSeverity)}`}>
                  {selectedFinding.contextualSeverity}
                </span>
              </div>
              <p className="text-gray-700 mb-4">{selectedFinding.description}</p>
              
              <div className="space-y-3">
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-1">Evidence Location</h4>
                  <div className="text-sm text-gray-600 bg-gray-50 px-3 py-2 rounded font-mono">
                    {selectedFinding.evidence.location}
                  </div>
                </div>

                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-1">Raw Observed</h4>
                  <div className="text-sm text-gray-600 bg-gray-900 text-green-400 px-3 py-2 rounded font-mono overflow-x-auto">
                    {selectedFinding.evidence.rawObserved}
                  </div>
                </div>

                {selectedFinding.evidence.reproduciblePayload && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-1">Reproducible Payload</h4>
                    <div className="text-sm text-gray-600 bg-gray-900 text-green-400 px-3 py-2 rounded font-mono overflow-x-auto">
                      {selectedFinding.evidence.reproduciblePayload}
                    </div>
                  </div>
                )}

                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-1">Remediation Steps</h4>
                  <ol className="list-decimal list-inside space-y-1 text-sm text-gray-600">
                    {selectedFinding.remediationSteps.map((step, idx) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ol>
                </div>

                {selectedFinding.cweId && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-1">CWE Reference</h4>
                    <div className="text-sm text-blue-600">
                      <a href={`https://cwe.mitre.org/data/definitions/${selectedFinding.cweId.replace('CWE-', '')}.html`} target="_blank" rel="noopener noreferrer">
                        {selectedFinding.cweId}
                      </a>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="text-center py-12 text-gray-500">
            <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <p>Select a finding to view evidence</p>
          </div>
        )}

        {/* Findings List */}
        {!selectedFinding && (
          <div className="space-y-2">
            <h3 className="text-sm font-medium text-gray-700 mb-2">All Findings ({findings.length})</h3>
            {findings.map((finding) => (
              <div
                key={finding.id}
                className={`p-3 rounded-lg border cursor-pointer hover:opacity-80 ${getSeverityColor(finding.contextualSeverity)}`}
                onClick={() => setSelectedFinding(finding)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="font-medium text-sm">{finding.title}</div>
                    <div className="text-xs mt-1 opacity-75">{finding.evidence.location}</div>
                  </div>
                  <span className={`text-xs font-semibold px-2 py-1 rounded ml-2 ${getSeverityColor(finding.contextualSeverity)}`}>
                    {finding.contextualSeverity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );

  const ScopeCoverage = () => (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
      <h3 className="text-sm font-medium text-gray-900 mb-3">Scope Coverage</h3>
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <h4 className="font-medium text-green-700 mb-2">In Scope</h4>
          <ul className="space-y-1 text-gray-600">
            <li>✓ HTTP Headers Analysis</li>
            <li>✓ Cookie Security</li>
            <li>✓ TLS Configuration</li>
            <li>✓ DNS Records</li>
            <li>✓ Technology Fingerprinting</li>
            <li>✓ Mixed Content Detection</li>
          </ul>
        </div>
        <div>
          <h4 className="font-medium text-red-700 mb-2">Out of Scope</h4>
          <ul className="space-y-1 text-gray-600">
            <li>✗ Active Exploitation</li>
            <li>✗ Business Logic Testing</li>
            <li>✗ Authentication Bypass</li>
            <li>✗ Authorization Testing</li>
            <li>✗ Input Validation (Deep)</li>
            <li>✗ Session Management (Deep)</li>
          </ul>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Top Control Bar */}
      <div className="bg-white border-b border-gray-200 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-600" />
            <h1 className="text-xl font-bold text-gray-900">AEGIS-X Enterprise Dashboard</h1>
          </div>
          
          {/* View Mode Toggle */}
          <div className="flex items-center gap-2 bg-gray-100 rounded-lg p-1">
            <button
              onClick={() => setViewMode('executive')}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                viewMode === 'executive'
                  ? 'bg-white text-gray-900 shadow-sm'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              Executive View
            </button>
            <button
              onClick={() => setViewMode('technical')}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                viewMode === 'technical'
                  ? 'bg-white text-gray-900 shadow-sm'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              Technical View
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="p-6">
        {viewMode === 'executive' ? <ExecutiveView /> : <TechnicalView />}
        <ScopeCoverage />
      </div>
    </div>
  );
};
