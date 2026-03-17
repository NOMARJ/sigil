import React, { useState, useEffect } from 'react';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
);

interface MigrationStats {
  total_scans: number;
  v1_scans: number;
  v2_scans: number;
  migration_percentage: number;
  avg_score_reduction: number;
  estimated_completion_date: string | null;
}

interface FalsePositiveComparison {
  scanner_version: string;
  total_findings: number;
  false_positives: number;
  false_positive_rate: number;
  avg_confidence: number;
}

interface PendingRescan {
  package_name: string;
  package_version: string;
  current_score: number;
  scan_date: string;
  priority: string;
}

interface DailyProgress {
  date: string;
  v2_scans: number;
  cumulative_percentage: number;
}

export default function MigrationStatus() {
  const [stats, setStats] = useState<MigrationStats | null>(null);
  const [falsePositives, setFalsePositives] = useState<FalsePositiveComparison[]>([]);
  const [pendingRescans, setPendingRescans] = useState<PendingRescan[]>([]);
  const [dailyProgress, setDailyProgress] = useState<DailyProgress[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchMigrationData();
  }, []);

  const fetchMigrationData = async () => {
    try {
      setLoading(true);
      
      const [statsRes, fpRes, pendingRes, progressRes] = await Promise.all([
        fetch('/api/admin/migration/status'),
        fetch('/api/admin/migration/false-positives'),
        fetch('/api/admin/migration/pending-rescans'),
        fetch('/api/admin/migration/daily-progress')
      ]);

      if (!statsRes.ok || !fpRes.ok || !pendingRes.ok || !progressRes.ok) {
        throw new Error('Failed to fetch migration data');
      }

      const [statsData, fpData, pendingData, progressData] = await Promise.all([
        statsRes.json(),
        fpRes.json(),
        pendingRes.json(),
        progressRes.json()
      ]);

      setStats(statsData);
      setFalsePositives(fpData);
      setPendingRescans(pendingData);
      setDailyProgress(progressData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load migration data');
    } finally {
      setLoading(false);
    }
  };

  const chartData = {
    labels: dailyProgress.map(d => d.date),
    datasets: [
      {
        label: 'Migration Progress (%)',
        data: dailyProgress.map(d => d.cumulative_percentage),
        borderColor: 'rgb(34, 197, 94)',
        backgroundColor: 'rgba(34, 197, 94, 0.1)',
        tension: 0.4
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top' as const,
      },
      title: {
        display: true,
        text: 'Scanner v2 Migration Progress'
      }
    },
    scales: {
      y: {
        beginAtZero: true,
        max: 100,
        ticks: {
          callback: function(value: any) {
            return value + '%';
          }
        }
      }
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'CRITICAL': return 'text-red-600';
      case 'HIGH': return 'text-orange-600';
      case 'MEDIUM': return 'text-yellow-600';
      default: return 'text-gray-600';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-green-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading migration status...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center text-red-600">
          <p>Error: {error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-8">Scanner v2 Migration Dashboard</h1>

      {/* Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-sm font-medium text-gray-500 mb-2">Migration Progress</h3>
          <p className="text-3xl font-bold text-green-600">{stats?.migration_percentage}%</p>
          <p className="text-sm text-gray-600 mt-2">
            {stats?.v2_scans} of {stats?.total_scans} scans
          </p>
          {stats?.estimated_completion_date && (
            <p className="text-xs text-gray-500 mt-1">
              Est. completion: {stats.estimated_completion_date}
            </p>
          )}
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-sm font-medium text-gray-500 mb-2">Score Reduction</h3>
          <p className="text-3xl font-bold text-blue-600">{stats?.avg_score_reduction}%</p>
          <p className="text-sm text-gray-600 mt-2">Average improvement</p>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-sm font-medium text-gray-500 mb-2">Remaining v1 Scans</h3>
          <p className="text-3xl font-bold text-orange-600">{stats?.v1_scans}</p>
          <p className="text-sm text-gray-600 mt-2">Pending migration</p>
        </div>
      </div>

      {/* Progress Chart */}
      <div className="bg-white rounded-lg shadow p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4">Daily Migration Progress</h2>
        {dailyProgress.length > 0 ? (
          <Line data={chartData} options={chartOptions} />
        ) : (
          <p className="text-gray-500">No migration data available</p>
        )}
      </div>

      {/* False Positive Comparison */}
      <div className="bg-white rounded-lg shadow p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4">False Positive Rate Comparison</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {falsePositives.map(fp => (
            <div key={fp.scanner_version} className="border rounded-lg p-4">
              <h3 className="font-semibold mb-2">
                Scanner v{fp.scanner_version}
              </h3>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-gray-600">Total Findings:</span>
                  <span className="font-medium">{fp.total_findings}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">False Positives:</span>
                  <span className="font-medium">{fp.false_positives}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">FP Rate:</span>
                  <span className={`font-bold ${
                    fp.false_positive_rate < 10 ? 'text-green-600' : 'text-red-600'
                  }`}>
                    {fp.false_positive_rate}%
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Avg Confidence:</span>
                  <span className="font-medium">{(fp.avg_confidence * 100).toFixed(0)}%</span>
                </div>
              </div>
            </div>
          ))}
        </div>
        {falsePositives.length >= 2 && (
          <div className="mt-4 p-4 bg-green-50 rounded-lg">
            <p className="text-green-800">
              <span className="font-semibold">Improvement: </span>
              {(falsePositives[0].false_positive_rate - falsePositives[1].false_positive_rate).toFixed(1)}% 
              reduction in false positive rate
            </p>
          </div>
        )}
      </div>

      {/* Pending High-Priority Rescans */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4">Pending High-Priority Rescans</h2>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Package</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Version</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Score</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Priority</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Scan</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {pendingRescans.map((pkg, idx) => (
                <tr key={idx}>
                  <td className="px-4 py-3 text-sm font-medium text-gray-900">{pkg.package_name}</td>
                  <td className="px-4 py-3 text-sm text-gray-600">{pkg.package_version}</td>
                  <td className="px-4 py-3 text-sm text-gray-900">{pkg.current_score}</td>
                  <td className={`px-4 py-3 text-sm font-semibold ${getPriorityColor(pkg.priority)}`}>
                    {pkg.priority}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600">{pkg.scan_date}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}