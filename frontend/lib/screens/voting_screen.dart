import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

/// સુરક્ષિત મતદાન સ્ક્રીન (સંસ્થાની ચૂંટણી માટે).
///
/// જૂના ડેમો વર્ઝનથી મુખ્ય તફાવત:
///  * ઓળખ: સભ્ય ID + મોબાઈલ OTP (Aadhaar નહીં)
///  * મતદાન, "મત આપ્યો કે નહીં" અને પરિણામ બધું ફક્ત સર્વર પર; ફોનમાં કોઈ લોકલ નકલ નહીં
///  * સર્વર જવાબ ન આપે તો મત "સફળ" બતાવાતો નથી
///  * ડેમો બટનો, રીસેટ બટન અને નકલી ફિંગરપ્રિન્ટ કાઢી નાખ્યા છે
class VotingScreen extends StatefulWidget {
  final String serverUrl;
  const VotingScreen({super.key, required this.serverUrl});

  @override
  State<VotingScreen> createState() => _VotingScreenState();
}

class _ApiError implements Exception {
  final String message;
  final int? status;
  _ApiError(this.message, [this.status]);
}

enum _Step { login, otp, ballot, done }

class _VotingScreenState extends State<VotingScreen> {
  final _memberCtrl = TextEditingController();
  final _mobileCtrl = TextEditingController();
  final _otpCtrl = TextEditingController();

  _Step _step = _Step.login;
  bool _loading = false;
  String? _error;
  String? _token;
  String _voterName = '';
  String _title = '';
  List<Map<String, dynamic>> _candidates = [];
  int? _selectedId;
  String? _receipt;
  Map<String, dynamic>? _status;

  String get _base {
    final u = widget.serverUrl.replaceAll(RegExp(r'/api/scan-poster/?$'), '');
    return u.replaceAll(RegExp(r'/+$'), '');
  }

  @override
  void initState() {
    super.initState();
    _loadStatus();
  }

  @override
  void dispose() {
    _memberCtrl.dispose();
    _mobileCtrl.dispose();
    _otpCtrl.dispose();
    super.dispose();
  }

  // ------------------------------------------------------------------ API
  Future<Map<String, dynamic>> _call(String method, String path, {Map<String, dynamic>? body}) async {
    final uri = Uri.parse('$_base/api/v2$path');
    final headers = {
      'Content-Type': 'application/json',
      if (_token != null) 'Authorization': 'Bearer $_token',
    };
    try {
      // Render ફ્રી સર્વર સૂતું હોય તો પહેલો જવાબ ધીમો હોય: લાંબો timeout
      final res = method == 'GET'
          ? await http.get(uri, headers: headers).timeout(const Duration(seconds: 45))
          : await http.post(uri, headers: headers, body: jsonEncode(body ?? {})).timeout(const Duration(seconds: 45));
      final data = jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>;
      if (res.statusCode >= 200 && res.statusCode < 300) return data;
      throw _ApiError(data['message']?.toString() ?? 'કંઈક ખોટું થયું (${res.statusCode})', res.statusCode);
    } on _ApiError {
      rethrow;
    } on TimeoutException {
      throw _ApiError('સર્વર જવાબ આપતું નથી. થોડી વાર પછી ફરી પ્રયાસ કરો.');
    } catch (_) {
      throw _ApiError('ઇન્ટરનેટ કનેક્શન કે સર્વર તપાસો.');
    }
  }

  Future<void> _run(Future<void> Function() action) async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      await action();
    } on _ApiError catch (e) {
      if (e.status == 401 && _step == _Step.ballot) {
        _token = null;
        _step = _Step.login;
      }
      _error = e.message;
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _loadStatus() async {
    try {
      final d = await _call('GET', '/status');
      if (mounted) setState(() => _status = d);
    } on _ApiError catch (e) {
      if (mounted) setState(() => _error = e.message);
    }
  }

  Future<void> _requestOtp() => _run(() async {
        final id = _memberCtrl.text.trim();
        final mobile = _mobileCtrl.text.replaceAll(RegExp(r'\D'), '');
        if (id.isEmpty || mobile.length < 10) {
          throw _ApiError('સભ્ય ID અને ૧૦-અંકનો મોબાઈલ નંબર દાખલ કરો.');
        }
        await _call('POST', '/auth/request-otp', body: {'member_id': id, 'mobile': mobile});
        _otpCtrl.clear();
        setState(() => _step = _Step.otp);
      });

  Future<void> _verifyOtp() => _run(() async {
        final d = await _call('POST', '/auth/verify-otp', body: {
          'member_id': _memberCtrl.text.trim(),
          'otp': _otpCtrl.text.trim(),
        });
        _token = d['token'] as String;
        _voterName = d['full_name']?.toString() ?? '';
        if (d['already_voted'] == true) {
          _token = null;
          throw _ApiError('તમે મત આપી ચૂક્યા છો.');
        }
        final b = await _call('GET', '/ballot');
        _title = b['title']?.toString() ?? '';
        _candidates = List<Map<String, dynamic>>.from(b['candidates'] as List);
        _selectedId = null;
        setState(() => _step = _Step.ballot);
      });

  Future<void> _castVote() async {
    final cand = _candidates.firstWhere((c) => c['id'] == _selectedId, orElse: () => {});
    if (cand.isEmpty) return;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('મતની પુષ્ટિ'),
        content: Text('તમે "${cand['name']}" ને મત આપો છો.\n\nમત આપ્યા પછી બદલી શકાશે નહીં.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('રદ કરો')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('હા, મત આપો')),
        ],
      ),
    );
    if (ok != true) return;

    await _run(() async {
      try {
        final d = await _call('POST', '/vote', body: {'candidate_id': _selectedId});
        HapticFeedback.heavyImpact();
        _receipt = d['receipt']?.toString();
        _token = null; // સત્ર તરત પૂરું
        setState(() => _step = _Step.done);
      } on _ApiError catch (e) {
        // નેટવર્ક તૂટે તો મત નોંધાયો હોઈ પણ શકે: સાચું સ્ટેટસ જાણવા ફરી લૉગિન કરો
        if (e.status == null) {
          throw _ApiError('${e.message}\nમત નોંધાયો કે નહીં તે ચકાસવા ફરી લૉગિન કરો. '
              'જો મત નોંધાઈ ગયો હશે તો "તમે મત આપી ચૂક્યા છો" દેખાશે.');
        }
        rethrow;
      }
    });
  }

  Future<void> _showResults() => _run(() async {
        final d = await _call('GET', '/results');
        if (!mounted) return;
        final rows = List<Map<String, dynamic>>.from(d['results'] as List);
        await showModalBottomSheet(
          context: context,
          isScrollControlled: true,
          builder: (_) => DraggableScrollableSheet(
            expand: false,
            builder: (ctx, sc) => ListView(
              controller: sc,
              padding: const EdgeInsets.all(16),
              children: [
                Text(d['title']?.toString() ?? 'પરિણામ', style: Theme.of(ctx).textTheme.titleLarge),
                const SizedBox(height: 4),
                Text('કુલ મત: ${d['total_votes']} / ${d['registered']}  (${d['turnout_percentage']}%)'),
                const Divider(),
                for (final r in rows)
                  ListTile(
                    dense: true,
                    title: Text('${r['name']}'),
                    subtitle: Text('${r['party'] ?? ''}  •  વોર્ડ ${r['ward_no']}'),
                    trailing: Text('${r['votes']}', style: const TextStyle(fontWeight: FontWeight.bold)),
                  ),
              ],
            ),
          ),
        );
      });

  void _reset() {
    setState(() {
      _step = _Step.login;
      _token = null;
      _error = null;
      _selectedId = null;
      _receipt = null;
      _memberCtrl.clear();
      _mobileCtrl.clear();
      _otpCtrl.clear();
    });
    _loadStatus();
  }

  // ------------------------------------------------------------------- UI
  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _statusCard(),
          const SizedBox(height: 12),
          if (_error != null)
            Card(
              color: Theme.of(context).colorScheme.errorContainer,
              child: Padding(padding: const EdgeInsets.all(12), child: Text(_error!)),
            ),
          if (_loading) const Padding(padding: EdgeInsets.all(16), child: Center(child: CircularProgressIndicator())),
          if (!_loading) ...switch (_step) {
            _Step.login => _loginView(),
            _Step.otp => _otpView(),
            _Step.ballot => _ballotView(),
            _Step.done => _doneView(),
          },
          const SizedBox(height: 24),
          const Text(
            'નોંધ: આ સંસ્થાની આંતરિક ચૂંટણી માટેની એપ છે. તે ચૂંટણી પંચની સત્તાવાર એપ નથી અને '
            'સરકારી ચૂંટણીના મતદાન માટે માન્ય નથી.',
            style: TextStyle(fontSize: 12, color: Colors.grey),
          ),
        ],
      ),
    );
  }

  Widget _statusCard() {
    final s = _status;
    String line;
    switch (s?['state']) {
      case 'open':
        line = 'મતદાન ચાલુ છે • મત પડ્યા: ${s!['voted']} / ${s['registered']}';
      case 'not_started':
        line = 'મતદાન હજી શરૂ થયું નથી';
      case 'closed':
        line = 'મતદાન પૂરું થયું છે';
      case 'not_configured':
        line = 'ચૂંટણી હજી ગોઠવાઈ નથી';
      default:
        line = 'સ્થિતિ મેળવી રહ્યા છીએ…';
    }
    return Card(
      child: ListTile(
        leading: const Icon(Icons.how_to_vote),
        title: Text(s?['title']?.toString() ?? 'Smart Voter'),
        subtitle: Text(line),
        trailing: IconButton(icon: const Icon(Icons.refresh), onPressed: _loadStatus),
      ),
    );
  }

  List<Widget> _loginView() => [
        TextField(
          controller: _memberCtrl,
          textCapitalization: TextCapitalization.characters,
          decoration: const InputDecoration(labelText: 'સભ્ય ID', border: OutlineInputBorder()),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _mobileCtrl,
          keyboardType: TextInputType.phone,
          inputFormatters: [FilteringTextInputFormatter.allow(RegExp(r'[0-9+ ]'))],
          decoration: const InputDecoration(labelText: 'નોંધાયેલ મોબાઈલ નંબર', border: OutlineInputBorder()),
        ),
        const SizedBox(height: 16),
        FilledButton.icon(onPressed: _requestOtp, icon: const Icon(Icons.sms), label: const Text('OTP મોકલો')),
        if (_status?['state'] == 'closed')
          TextButton.icon(onPressed: _showResults, icon: const Icon(Icons.bar_chart), label: const Text('પરિણામ જુઓ')),
      ];

  List<Widget> _otpView() => [
        const Text('મોબાઈલ પર આવેલો ૬-અંકનો OTP દાખલ કરો (૫ મિનિટ માન્ય).'),
        const SizedBox(height: 12),
        TextField(
          controller: _otpCtrl,
          keyboardType: TextInputType.number,
          maxLength: 6,
          inputFormatters: [FilteringTextInputFormatter.digitsOnly],
          decoration: const InputDecoration(labelText: 'OTP', border: OutlineInputBorder()),
        ),
        FilledButton(onPressed: _verifyOtp, child: const Text('ચકાસો')),
        TextButton(onPressed: _reset, child: const Text('પાછા જાઓ')),
      ];

  List<Widget> _ballotView() => [
        Text('નમસ્તે $_voterName', style: Theme.of(context).textTheme.titleMedium),
        Text(_title),
        const SizedBox(height: 8),
        for (final c in _candidates)
          Card(
            child: RadioListTile<int>(
              value: c['id'] as int,
              groupValue: _selectedId,
              onChanged: (v) => setState(() => _selectedId = v),
              title: Text('${c['name']}'),
              subtitle: (c['party'] ?? '').toString().isEmpty ? null : Text('${c['party']}'),
            ),
          ),
        const SizedBox(height: 12),
        FilledButton.icon(
          onPressed: _selectedId == null ? null : _castVote,
          icon: const Icon(Icons.how_to_vote),
          label: const Text('મત આપો'),
        ),
      ];

  List<Widget> _doneView() => [
        const Icon(Icons.check_circle, color: Colors.green, size: 64),
        const Center(child: Text('તમારો મત નોંધાઈ ગયો છે.', style: TextStyle(fontSize: 18))),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            title: const Text('રસીદ કોડ'),
            subtitle: Text(_receipt ?? '-', style: const TextStyle(fontSize: 20, letterSpacing: 2)),
            trailing: IconButton(
              icon: const Icon(Icons.copy),
              onPressed: () => Clipboard.setData(ClipboardData(text: _receipt ?? '')),
            ),
          ),
        ),
        const Text('આ કોડમાં તમારી પસંદગી નથી; તે ફક્ત મત ગણાયો તેનો પુરાવો છે.',
            style: TextStyle(fontSize: 12, color: Colors.grey)),
        TextButton(onPressed: _reset, child: const Text('પૂર્ણ')),
      ];
}
