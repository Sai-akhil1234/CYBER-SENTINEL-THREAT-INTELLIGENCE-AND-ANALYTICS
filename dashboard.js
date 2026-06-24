// CyberGuard Dashboard JS - Rebuild
(function () {
    'use strict';

    function set(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    // Close welcome popup
    window.closeWelcomePopup = function() {
        var popup = document.getElementById('welcome-popup');
        if (popup) {
            popup.style.display = 'none';
        }
    };

    function makeChart(id, cfg) {
        try {
            var canvas = document.getElementById(id);
            if (!canvas) { console.warn('Canvas not found: ' + id); return; }
            var ctx = canvas.getContext('2d');
            new Chart(ctx, cfg);
        } catch (e) {
            console.error('Chart error [' + id + ']:', e);
        }
    }

    function run(data) {
        // ── Welcome
        set('welcome_msg', 'Welcome, ' + (data.username || 'User'));

        // ── KPI
        set('total_records', Number(data.total_records).toLocaleString());
        set('malicious_count', Number(data.labels.Malicious).toLocaleString());
        set('genuine_count', Number(data.labels.Genuine).toLocaleString());
        var rate = (data.labels.Malicious / data.total_records * 100).toFixed(1);
        set('detection_rate', rate + '%');

        // ── ML Metrics
        set('lr_acc', data.models.lr.accuracy + '%');
        set('knn_acc', data.models.knn.accuracy + '%');
        set('lr_precision', data.models.lr.precision + '%');
        set('knn_precision', data.models.knn.precision + '%');

        // ── Pie 1: Before Removal
        makeChart('pieChartBefore', {
            type: 'pie',
            data: {
                labels: ['Malicious', 'Genuine Users'],
                datasets: [{
                    data: [data.before_removal.Malicious, data.before_removal.Genuine],
                    backgroundColor: ['#ef4444', '#22c55e'],
                    borderColor: '#0f172a',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom' } }
            }
        });

        // ── Pie 2: After Removal
        makeChart('pieChartAfter', {
            type: 'pie',
            data: {
                labels: ['Genuine Users', 'Remaining Malicious'],
                datasets: [{
                    data: [data.after_removal.Genuine, data.after_removal.Remaining_Malicious],
                    backgroundColor: ['#22c55e', '#ef4444'],
                    borderColor: '#0f172a',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom' } }
            }
        });

        // ── Bar: Protocols All vs Malicious
        var protoKeys = Object.keys(data.protocols.all);
        makeChart('barChart', {
            type: 'bar',
            data: {
                labels: protoKeys,
                datasets: [
                    {
                        label: 'All Requests',
                        data: protoKeys.map(function (k) { return data.protocols.all[k]; }),
                        backgroundColor: 'rgba(99,102,241,0.85)',
                        borderRadius: 6
                    },
                    {
                        label: 'Malicious',
                        data: protoKeys.map(function (k) { return data.protocols.malicious[k] || 0; }),
                        backgroundColor: 'rgba(239,68,68,0.85)',
                        borderRadius: 6
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } },
                    x: { grid: { display: false } }
                },
                plugins: { legend: { position: 'bottom' } }
            }
        });

        // ── Horizontal Bar: All Source IPs
        makeChart('srcAllChart', {
            type: 'bar',
            data: {
                labels: Object.keys(data.src_ips.all),
                datasets: [{
                    label: 'Requests',
                    data: Object.values(data.src_ips.all),
                    backgroundColor: 'rgba(34,197,94,0.8)',
                    borderRadius: 5
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { grid: { display: false } }
                },
                plugins: { legend: { display: false } }
            }
        });

        // ── Horizontal Bar: Malicious Source IPs
        makeChart('srcAttackChart', {
            type: 'bar',
            data: {
                labels: Object.keys(data.src_ips.malicious),
                datasets: [{
                    label: 'Attacks',
                    data: Object.values(data.src_ips.malicious),
                    backgroundColor: 'rgba(239,68,68,0.8)',
                    borderRadius: 5
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { grid: { display: false } }
                },
                plugins: { legend: { display: false } }
            }
        });

        // ── Bar: Null Values
        makeChart('nullChart', {
            type: 'bar',
            data: {
                labels: Object.keys(data.null_values),
                datasets: [{
                    label: 'Null Count',
                    data: Object.values(data.null_values),
                    backgroundColor: 'rgba(248,113,113,0.7)',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true },
                    x: { grid: { display: false }, ticks: { autoSkip: false, maxRotation: 60 } }
                },
                plugins: { legend: { display: false } }
            }
        });

        // ── Table: describe()
        var desc = data.describe;
        if (!desc) return;
        var statKeys = ['count', 'mean', 'std', 'min', '25%', '50%', '75%', 'max'];
        var cols = Object.keys(desc);
        var head = document.getElementById('descHead');
        var body = document.getElementById('descBody');
        if (!head || !body) return;

        var hr = document.createElement('tr');
        var thCells = '<th>Statistic</th>';
        cols.forEach(function (c) { thCells += '<th>' + c + '</th>'; });
        hr.innerHTML = thCells;
        head.appendChild(hr);

        statKeys.forEach(function (stat) {
            var tr = document.createElement('tr');
            var cells = '<td>' + stat + '</td>';
            cols.forEach(function (col) {
                var v = (desc[col] && desc[col][stat] !== undefined && desc[col][stat] !== null)
                    ? Number(desc[col][stat]).toLocaleString(undefined, { maximumFractionDigits: 3 })
                    : '—';
                cells += '<td>' + v + '</td>';
            });
            tr.innerHTML = cells;
            body.appendChild(tr);
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';

        fetch('/api/stats')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.error) { console.error('API error:', data.error); return; }
                run(data);
            })
            .catch(function (err) { console.error('Fetch failed:', err); });
    });
})();
