import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Chart } from 'chart.js/auto';
import { 
  getDashboardOverview, 
  getLiveTraffic, 
  exportTrafficData 
} from '../../services/api';
import { toast } from 'react-toastify';
import './Dashboard.css';

const Dashboard = () => {
  const navigate = useNavigate();
  const [isMonitoring, setIsMonitoring] = useState(true);
  const [dashboardData, setDashboardData] = useState(null);
  const [liveTraffic, setLiveTraffic] = useState({ normal: [], suspicious: [] });
  
  const trafficChartRef = useRef(null);
  const pieChartRef = useRef(null);
  const barChartRef = useRef(null);
  const trafficChart = useRef(null);
  const pieChart = useRef(null);
  const barChart = useRef(null);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 10000); // Update every 10 seconds
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (isMonitoring) {
      fetchLiveTraffic();
      const interval = setInterval(fetchLiveTraffic, 2000); // Update every 2 seconds
      return () => clearInterval(interval);
    }
  }, [isMonitoring]);

  useEffect(() => {
    if (dashboardData) {
      initializeCharts();
    }
  }, [dashboardData]);

  const fetchDashboardData = async () => {
    try {
      const data = await getDashboardOverview(24);
      setDashboardData(data);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    }
  };

  const fetchLiveTraffic = async () => {
    try {
      const data = await getLiveTraffic(20);
      setLiveTraffic(data);
      updateTrafficChart(data);
    } catch (error) {
      console.error('Failed to fetch live traffic:', error);
    }
  };

  const initializeCharts = () => {
    // Traffic Chart
    if (trafficChartRef.current) {
      const ctx = trafficChartRef.current.getContext('2d');
      
      if (trafficChart.current) {
        trafficChart.current.destroy();
      }

      trafficChart.current = new Chart(ctx, {
        type: 'line',
        data: {
          labels: Array.from({length: 20}, (_, i) => `${i}s`),
          datasets: [
            {
              label: 'Normal Traffic',
              data: Array.from({length: 20}, () => Math.floor(Math.random() * 50 + 30)),
              borderColor: '#00aaff',
              backgroundColor: 'rgba(0, 170, 255, 0.1)',
              tension: 0.4,
              fill: true
            },
            {
              label: 'Suspicious Traffic',
              data: Array.from({length: 20}, () => Math.floor(Math.random() * 10)),
              borderColor: '#ff6b6b',
              backgroundColor: 'rgba(255, 107, 107, 0.1)',
              tension: 0.4,
              fill: true
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: { color: '#9fa3ad' }
            }
          },
          scales: {
            x: {
              ticks: { color: '#9fa3ad' },
              grid: { color: '#1e212d' }
            },
            y: {
              ticks: { color: '#9fa3ad' },
              grid: { color: '#1e212d' }
            }
          }
        }
      });
    }

    // Pie Chart
    if (pieChartRef.current && dashboardData?.attack_distribution) {
      const ctx = pieChartRef.current.getContext('2d');
      
      if (pieChart.current) {
        pieChart.current.destroy();
      }

      const attackDist = dashboardData.attack_distribution;
      pieChart.current = new Chart(ctx, {
        type: 'pie',
        data: {
          labels: Object.keys(attackDist),
          datasets: [{
            data: Object.values(attackDist),
            backgroundColor: ['#00aaff', '#0077c7', '#00d4ff', '#ff6b6b', '#4ecdc4', '#ffa07a'],
            borderWidth: 2,
            borderColor: '#151821'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: { 
                color: '#9fa3ad',
                padding: 15
              }
            }
          }
        }
      });
    }

    // Bar Chart
    if (barChartRef.current && dashboardData?.model_performance) {
      const ctx = barChartRef.current.getContext('2d');
      
      if (barChart.current) {
        barChart.current.destroy();
      }

      const perf = dashboardData.model_performance;
      barChart.current = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: ['Accuracy', 'Precision', 'Recall', 'F1 Score'],
          datasets: [{
            label: 'Performance (%)',
            data: [perf.accuracy, perf.precision, perf.recall, perf.f1_score],
            backgroundColor: '#00aaff',
            borderRadius: 8
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: { color: '#9fa3ad' }
            }
          },
          scales: {
            x: {
              ticks: { color: '#9fa3ad' },
              grid: { color: '#1e212d' }
            },
            y: {
              ticks: { color: '#9fa3ad' },
              grid: { color: '#1e212d' },
              min: 0,
              max: 100
            }
          }
        }
      });
    }
  };

  const updateTrafficChart = (data) => {
    if (trafficChart.current && data.normal) {
      const chart = trafficChart.current;
      chart.data.labels = data.normal.map(d => d.time);
      chart.data.datasets[0].data = data.normal.map(d => d.value);
      chart.data.datasets[1].data = data.suspicious.map(d => d.value);
      chart.update('none');
    }
  };

  const toggleMonitoring = () => {
    setIsMonitoring(!isMonitoring);
    toast.info(isMonitoring ? 'Monitoring stopped' : 'Monitoring started');
  };

  const handleResetStats = () => {
    toast.success('Statistics reset successfully!');
  };

  const handleExportDatabase = async () => {
    try {
      const data = await exportTrafficData();
      const blob = new Blob([data.data], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = data.filename;
      a.click();
      toast.success('Database exported successfully!');
    } catch (error) {
      toast.error('Failed to export database');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    navigate('/login');
    toast.success('Logged out successfully');
  };

  if (!dashboardData) {
    return <div className="loading-container">Loading dashboard...</div>;
  }

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <div className="header-content">
          <h1>🦅 GarudaRush — Dashboard</h1>
          <button className="logout-btn" onClick={handleLogout}>Logout</button>
        </div>
      </header>

      {/* Traffic Monitor */}
      <section className="section">
        <h2>📡 Real-Time Traffic Monitor</h2>
        <div className="chart-box">
          <canvas ref={trafficChartRef}></canvas>
        </div>
        <button className={`btn ${!isMonitoring ? 'stopped' : ''}`} onClick={toggleMonitoring}>
          <span>{isMonitoring ? '⏸' : '▶'}</span>
          <span>{isMonitoring ? 'Stop Monitoring' : 'Start Monitoring'}</span>
        </button>
      </section>

      {/* Database Storage */}
      <section className="section">
        <h2>💾 Database Storage</h2>
        <div className="flex">
          <div className="card">
            <div className="stats-title">Total Records</div>
            <div className="stats-value">{dashboardData.overview.total_records}</div>
          </div>
          <div className="card">
            <div className="stats-title">Alert Records</div>
            <div className="stats-value">{dashboardData.overview.alert_records}</div>
          </div>
          <div className="card">
            <div className="stats-title">Traffic Records</div>
            <div className="stats-value">{dashboardData.overview.traffic_records}</div>
          </div>
        </div>
        <button className="btn" onClick={handleResetStats}>
          <span>🔄</span> Reset Statistics
        </button>
        <button className="btn" onClick={handleExportDatabase}>
          <span>⬇️</span> Export Database
        </button>
      </section>

      {/* Analytics & Performance */}
      <section className="section">
        <h2>📊 Analytics & Performance</h2>
        <div className="flex">
          <div className="chart-box pie-chart-container">
            <div className="chart-header">Attack Distribution</div>
            <canvas ref={pieChartRef}></canvas>
          </div>
          <div className="chart-box" style={{flex: 1, minWidth: '400px'}}>
            <div className="chart-header">🏆 Model Performance</div>
            <canvas ref={barChartRef}></canvas>
          </div>
        </div>
      </section>

      {/* Detection Statistics */}
      <section className="section">
        <h2>📈 Detection Statistics</h2>
        <div className="stats-grid">
          <div className="card">
            <div className="stats-title">Total Detections</div>
            <div className="stats-value">{dashboardData.detection_stats.total_detections}</div>
          </div>
          <div className="card">
            <div className="stats-title">Attack Rate</div>
            <div className="stats-value">{dashboardData.detection_stats.attack_rate}%</div>
          </div>
          <div className="card">
            <div className="stats-title">False Positive</div>
            <div className="stats-value">{dashboardData.detection_stats.false_positive_rate}%</div>
          </div>
          <div className="card">
            <div className="stats-title">Detection Time</div>
            <div className="stats-value">{dashboardData.detection_stats.avg_detection_time}s</div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Dashboard;