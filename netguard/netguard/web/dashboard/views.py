from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db import connections
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from datetime import timedelta
import json


def login_view(request):
    """Login page"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    error = None
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            error = 'Invalid username or password'
    
    return render(request, 'dashboard/login.html', {'error': error})


def logout_view(request):
    """Logout"""
    logout(request)
    return redirect('login')


@login_required
def dashboard_view(request):
    """Main dashboard"""
    return render(request, 'dashboard/dashboard.html')


@login_required
def connections_view(request):
    """Connections list page"""
    return render(request, 'dashboard/connections.html')


@login_required
def threats_view(request):
    """Threats page"""
    return render(request, 'dashboard/threats.html')


@login_required
def alerts_view(request):
    """Alerts page"""
    return render(request, 'dashboard/alerts.html')


@login_required
def api_stats(request):
    """API: Get current statistics"""
    try:
        with connections['default'].cursor() as cursor:
            # Connections in last 5 minutes
            cursor.execute("""
                SELECT COUNT(*), 
                       COUNT(DISTINCT src_ip),
                       SUM(bytes_in + bytes_out),
                       COUNT(CASE WHEN threat_score > 0.5 THEN 1 END)
                FROM connections 
                WHERE time > NOW() - INTERVAL '5 minutes'
            """)
            row = cursor.fetchone()
            
            stats = {
                'connections_5min': row[0] or 0,
                'unique_sources': row[1] or 0,
                'total_bytes': row[2] or 0,
                'threats_5min': row[3] or 0,
            }
            
            # Protocol distribution
            cursor.execute("""
                SELECT protocol, COUNT(*) as count
                FROM connections 
                WHERE time > NOW() - INTERVAL '5 minutes'
                GROUP BY protocol
                ORDER BY count DESC
            """)
            stats['protocols'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Top destinations
            cursor.execute("""
                SELECT dst_ip, domain, COUNT(*) as count
                FROM connections 
                WHERE time > NOW() - INTERVAL '5 minutes'
                GROUP BY dst_ip, domain
                ORDER BY count DESC
                LIMIT 10
            """)
            stats['top_destinations'] = [
                {'ip': row[0], 'domain': row[1] or '-', 'count': row[2]}
                for row in cursor.fetchall()
            ]
            
            # Unacknowledged alerts count
            cursor.execute("""
                SELECT COUNT(*) FROM alerts 
                WHERE acknowledged = FALSE 
                AND time > NOW() - INTERVAL '24 hours'
            """)
            stats['unacknowledged_alerts'] = cursor.fetchone()[0] or 0
            
            return JsonResponse(stats)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def api_connections(request):
    """API: Get recent connections"""
    try:
        minutes = int(request.GET.get('minutes', 5))
        limit = int(request.GET.get('limit', 100))
        
        with connections['default'].cursor() as cursor:
            cursor.execute("""
                SELECT time, src_ip, src_port, dst_ip, dst_port, domain,
                       protocol, bytes_in, bytes_out, duration,
                       threat_score, threat_type
                FROM connections 
                WHERE time > NOW() - INTERVAL '%s minutes'
                ORDER BY time DESC
                LIMIT %s
            """, [minutes, limit])
            
            columns = [desc[0] for desc in cursor.description]
            connections_list = []
            
            for row in cursor.fetchall():
                conn = dict(zip(columns, row))
                conn['time'] = conn['time'].isoformat() if conn['time'] else None
                connections_list.append(conn)
            
            return JsonResponse({
                'connections': connections_list,
                'count': len(connections_list)
            })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def api_threats(request):
    """API: Get threats"""
    try:
        with connections['default'].cursor() as cursor:
            cursor.execute("""
                SELECT time, src_ip, dst_ip, dst_port, protocol,
                       threat_score, threat_type, domain
                FROM connections 
                WHERE threat_score > 0.5
                AND time > NOW() - INTERVAL '24 hours'
                ORDER BY time DESC
                LIMIT 100
            """)
            
            columns = [desc[0] for desc in cursor.description]
            threats = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            return JsonResponse({'threats': threats, 'count': len(threats)})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def api_alerts_recent(request):
    """API: Get recent alerts for navbar"""
    try:
        with connections['default'].cursor() as cursor:
            # Get unacknowledged count
            cursor.execute("""
                SELECT COUNT(*) FROM alerts 
                WHERE acknowledged = FALSE 
                AND time > NOW() - INTERVAL '24 hours'
            """)
            unacknowledged_count = cursor.fetchone()[0] or 0
            
            # Get recent alerts
            cursor.execute("""
                SELECT id, time, alert_type, severity, message, 
                       src_ip, dst_ip, acknowledged
                FROM alerts 
                WHERE time > NOW() - INTERVAL '24 hours'
                ORDER BY time DESC
                LIMIT 10
            """)
            
            columns = [desc[0] for desc in cursor.description]
            alerts = []
            
            for row in cursor.fetchall():
                alert = dict(zip(columns, row))
                alert['time'] = alert['time'].isoformat() if alert['time'] else None
                
                # Format title based on severity
                severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
                alert['title'] = f"{severity_emoji.get(alert['severity'], '⚪')} {alert['alert_type']}"
                alerts.append(alert)
            
            return JsonResponse({
                'alerts': alerts,
                'unacknowledged_count': unacknowledged_count
            })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@csrf_exempt
def api_alerts_acknowledge(request, alert_id):
    """API: Acknowledge an alert"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        with connections['default'].cursor() as cursor:
            cursor.execute("""
                UPDATE alerts 
                SET acknowledged = TRUE, 
                    acknowledged_by = %s,
                    acknowledged_at = NOW()
                WHERE id = %s
            """, [request.user.username, alert_id])
            
            return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def api_search(request):
    """API: Search historical data"""
    try:
        query = request.GET.get('q', '')
        start_time = request.GET.get('start')
        end_time = request.GET.get('end')
        
        where_clauses = []
        params = []
        
        if query:
            where_clauses.append("""
                (src_ip::text LIKE %s OR 
                 dst_ip::text LIKE %s OR 
                 domain LIKE %s)
            """)
            params.extend([f'%{query}%', f'%{query}%', f'%{query}%'])
        
        if start_time:
            where_clauses.append("time >= %s")
            params.append(start_time)
        
        if end_time:
            where_clauses.append("time <= %s")
            params.append(end_time)
        
        where_sql = ' AND '.join(where_clauses) if where_clauses else 'TRUE'
        
        with connections['default'].cursor() as cursor:
            cursor.execute(f"""
                SELECT time, src_ip, src_port, dst_ip, dst_port, domain,
                       protocol, bytes_in, bytes_out, duration,
                       threat_score, threat_type
                FROM connections 
                WHERE {where_sql}
                ORDER BY time DESC
                LIMIT 1000
            """, params)
            
            columns = [desc[0] for desc in cursor.description]
            results = []
            
            for row in cursor.fetchall():
                result = dict(zip(columns, row))
                result['time'] = result['time'].isoformat() if result['time'] else None
                results.append(result)
            
            return JsonResponse({
                'results': results,
                'count': len(results)
            })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
