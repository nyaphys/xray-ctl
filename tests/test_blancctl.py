import argparse
import contextlib
import io
import pathlib
import json
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
from unittest import mock

from app import blancctl


def sample(label, host):
    return blancctl.parse(
        f"vless://12345678-1234-1234-1234-123456789abc@{host}:443"
        f"?security=reality&type=tcp&flow=xtls-rprx-vision#{label}", 0
    )


class NodeCacheTests(unittest.TestCase):
    def setUp(self):
        # Unit tests must never append diagnostics to the live installation.
        patcher=mock.patch.object(blancctl,'log_event')
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_subscription_timeout_is_bounded_and_adaptive(self):
        with mock.patch.object(blancctl, 'load', return_value={}):
            self.assertEqual(blancctl.download_limits(), (2.5, 8))
        with mock.patch.object(blancctl, 'load', return_value={'seconds':1}):
            self.assertEqual(blancctl.download_limits(), (2, 5))
        with mock.patch.object(blancctl, 'load', return_value={'seconds':30}):
            self.assertEqual(blancctl.download_limits(), (4, 12))

    def test_identical_profiles_across_sources_merge_without_losing_provenance(self):
        first = sample('One label', 'same.example')
        second = sample('Another label', 'same.example')
        first['sources'], second['sources'] = ['first'], ['second']
        merged, current, retained = blancctl.merge_nodes([first, second], [])
        self.assertEqual((current, retained, len(merged)), (1, 0, 1))
        self.assertEqual(merged[0]['sources'], ['first', 'second'])
        duplicate = {**merged[0], 'sources':['third']}
        self.assertEqual(blancctl.compact_nodes([merged[0], duplicate])[0]['sources'],
                         ['first', 'second', 'third'])

    def test_multiple_sources_refresh_concurrently_and_preserves_failed_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            paths = dict(STATE=root, SUB=root/'subscription.url', SUBSCRIPTIONS=root/'subscriptions.json',
                         NODES=root/'nodes.json', RETAINED=root/'retained.json', PICK=root/'selected.json',
                         DOWNLOAD=root/'download.json', RAW=root/'subscription.raw', RAW_DIR=root/'raw')
            with mock.patch.multiple(blancctl, **paths):
                old = sample('Existing', 'old.example')
                old['sources'] = ['failed']
                blancctl.save(blancctl.NODES, [old])
                blancctl.save(blancctl.SUBSCRIPTIONS,
                              {'working':'https://example.invalid/a', 'failed':'https://example.invalid/b'})
                both_started = threading.Barrier(2)
                def fetch(name, *_):
                    both_started.wait(timeout=2)
                    if name == 'failed': raise RuntimeError('timeout')
                    new = sample('Fresh', 'fresh.example')
                    new['sources'] = [name]
                    return [new], 'vless://private', 0
                with mock.patch.object(blancctl, 'download_source', side_effect=fetch), \
                     contextlib.redirect_stdout(io.StringIO()), \
                     contextlib.redirect_stderr(io.StringIO()):
                    merged = blancctl.update()
                self.assertEqual({n['address'] for n in merged if not n['stale']},
                                 {'old.example', 'fresh.example'})
                self.assertEqual(len(blancctl.load(blancctl.RETAINED, [])), 0)
                self.assertEqual(len(list((root/'raw').glob('*.raw'))), 1)

    def test_unsupported_source_does_not_erase_cached_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with mock.patch.multiple(blancctl, STATE=root, SUB=root/'subscription.url',
                                     NODES=root/'nodes.json', RETAINED=root/'retained.json',
                                     RAW=root/'subscription.raw', DOWNLOAD=root/'download.json',
                                     SUBSCRIPTIONS=root/'subscriptions.json'):
                old = sample('Working before refresh', 'old.example')
                blancctl.save(blancctl.NODES, [old])
                blancctl.save(blancctl.SUBSCRIPTIONS, {'default':'https://example.invalid/sub'})
                with mock.patch.object(blancctl, 'download_source',
                                       return_value=([], 'trojan://unsupported', 1)), \
                     contextlib.redirect_stderr(io.StringIO()), \
                     self.assertRaises(SystemExit):
                    blancctl.update()
                self.assertEqual(blancctl.load(blancctl.NODES, []), [old])
                self.assertIn('trojan://unsupported', blancctl.RAW.read_text())

    def test_route_defaults_proxy_and_explicit_direct_rules_only(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(blancctl, 'ROUTES', pathlib.Path(tmp)/'routing.json'):
            config = blancctl.routing_config()
            self.assertEqual(config['default'], 'proxy')
            self.assertEqual(config['direct']['domains'], [])
            self.assertEqual(blancctl.routing_rules()[-1]['outboundTag'], 'proxy')
            blancctl.save(blancctl.ROUTES, {'default':'proxy',
                         'direct':{'domains':['example.ru', 'full:sub.example.ru'],
                                   'ips':['192.0.2.3']}})
            rules = blancctl.routing_rules()
            self.assertEqual(rules[-3]['domain'], ['domain:example.ru', 'full:sub.example.ru'])
            self.assertEqual(rules[-1]['outboundTag'], 'proxy')
            self.assertNotIn('geoip:ru', str(rules))

    @unittest.skipUnless(shutil.which('xray'), 'Xray is not installed')
    def test_split_routing_passes_xray_validation(self):
        node = blancctl.parse(
            'vless://12345678-1234-1234-1234-123456789abc@a.example:443?security=tls#Test', 0)
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(blancctl, 'ROUTES', pathlib.Path(tmp)/'routing.json'), \
             mock.patch.object(blancctl, 'physical_interface', return_value='wlan0'):
            blancctl.save(blancctl.ROUTES, {'default':'proxy',
                         'direct':{'domains':['example.ru'], 'ips':['203.0.113.0/24']},
                         'proxy':{'domains':['full:blocked.ru']}})
            config = blancctl.tun(node)
            config['inbounds'] = [{'listen':'127.0.0.1','port':18080,'protocol':'socks',
                                   'settings':{'udp':True},
                                   'sniffing':config['inbounds'][0]['sniffing']}]
            path = pathlib.Path(tmp)/'xray.json'
            path.write_text(json.dumps(config))
            result = subprocess.run(['xray','run','-test','-c',str(path)],capture_output=True,text=True)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_subscription_list_hides_private_urls(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(blancctl, 'SUBSCRIPTIONS', pathlib.Path(tmp)/'subscriptions.json'):
            blancctl.save(blancctl.SUBSCRIPTIONS, {'one':'https://secret.invalid/private'})
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                blancctl.subscription(argparse.Namespace(args=['list']))
            self.assertEqual(output.getvalue(), 'one\n')

    def test_source_removal_retains_unique_nodes_without_changing_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with mock.patch.multiple(blancctl, STATE=root, SUB=root/'subscription.url',
                                     SUBSCRIPTIONS=root/'subscriptions.json', NODES=root/'nodes.json',
                                     RETAINED=root/'retained.json', PICK=root/'selected.json'):
                unique = sample('From removed source', 'removed.example')
                unique['sources'] = ['removed']
                shared = sample('From both sources', 'shared.example')
                shared['id'] = 'node-002'
                shared['sources'] = ['removed', 'kept']
                blancctl.save(blancctl.NODES, [unique, shared])
                blancctl.save(blancctl.PICK, {'id':unique['id']})
                blancctl.save(blancctl.SUBSCRIPTIONS,
                              {'removed':'https://example.invalid/a', 'kept':'https://example.invalid/b'})
                with contextlib.redirect_stdout(io.StringIO()):
                    blancctl.subscription(argparse.Namespace(args=['remove','removed']))
                current, retained = blancctl.cached_nodes()
                self.assertEqual([n['address'] for n in current], ['shared.example'])
                self.assertEqual(current[0]['sources'], ['kept'])
                self.assertEqual([n['address'] for n in retained], ['removed.example'])
                self.assertEqual(blancctl.load(blancctl.PICK, {})['id'], unique['id'])
                self.assertEqual(blancctl.subscription_sources(),
                                 {'kept':'https://example.invalid/b'})

    def test_route_cli_saves_rules_without_live_restart(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(blancctl, 'ROUTES', pathlib.Path(tmp)/'routing.json'), \
             mock.patch.object(blancctl, 'select') as select, \
             contextlib.redirect_stdout(io.StringIO()):
            blancctl.route(argparse.Namespace(args=['add','direct','domain','example.ru']))
            self.assertEqual(blancctl.routing_config()['direct']['domains'],
                             ['domain:example.ru'])
            blancctl.route(argparse.Namespace(args=['remove','direct','domain','example.ru']))
            self.assertEqual(blancctl.routing_config()['direct']['domains'], [])
            select.assert_not_called()

    def test_nixos_sudo_wrapper_takes_priority_over_store_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrapper = pathlib.Path(tmp) / 'sudo'
            wrapper.touch(mode=0o755)
            with mock.patch.object(blancctl.shutil, 'which', return_value='/nix/store/unprivileged/bin/sudo'):
                self.assertEqual(blancctl.sudo_executable(wrapper), str(wrapper))

    def test_sudo_falls_back_to_path_outside_nixos(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(blancctl.shutil, 'which', return_value='/usr/bin/sudo'):
            self.assertEqual(blancctl.sudo_executable(pathlib.Path(tmp) / 'missing'), '/usr/bin/sudo')

    def test_reordering_keeps_ids_and_missing_nodes_are_retained(self):
        a = sample('Extra, Germany', 'a.example')
        b = sample('Extra, Turkey', 'b.example')
        a['id'], b['id'] = 'node-001', 'node-002'
        merged, current, retained = blancctl.merge_nodes(
            [sample('Extra, Germany', 'a.example'),
             sample('Extra, France', 'c.example'),
             sample('Extra, Germany', 'a.example')], [a, b]
        )
        self.assertEqual((current, retained), (2, 1))
        self.assertEqual(merged[0]['id'], 'node-001')
        self.assertFalse(merged[0]['stale'])
        self.assertTrue(merged[1]['id'].startswith('node-'))
        self.assertNotIn(merged[1]['id'], {'node-001', 'node-002'})
        self.assertEqual(merged[2]['id'], 'node-002')
        self.assertTrue(merged[2]['stale'])

    def test_renames_and_cached_duplicates_do_not_multiply_nodes(self):
        old = sample('Old name', 'a.example')
        duplicate = sample('Another old name', 'a.example')
        old['id'], duplicate['id'] = 'node-001', 'node-099'
        cached = [old, duplicate]
        for label in ('New name', 'Newer name', 'Newest name'):
            fetched = [sample(label, 'a.example'), sample(label, 'a.example')]
            cached, current, retained = blancctl.merge_nodes(fetched, cached, 'node-099')
            self.assertEqual((current, retained, len(cached)), (1, 0, 1))
            self.assertEqual(cached[0]['id'], 'node-099')
            self.assertEqual(cached[0]['label'], label)

    def test_distinct_connection_settings_remain_separate(self):
        first = sample('Same label', 'a.example')
        second = sample('Same label', 'a.example')
        second['short_id'] = 'different'
        merged, current, retained = blancctl.merge_nodes([first, second], [])
        self.assertEqual((current, retained, len(merged)), (2, 0, 2))
        self.assertNotEqual(merged[0]['id'], merged[1]['id'])

    def test_update_keeps_cache_without_exposing_subscription(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with mock.patch.multiple(blancctl, STATE=root, SUB=root/'subscription.url',
                                     NODES=root/'nodes.json', DOWNLOAD=root/'download.json',
                                     RAW=root/'subscription.raw', PICK=root/'selected.json',
                                     RETAINED=root/'retained-nodes.json'):
                old = sample('Extra, Turkey', 'b.example')
                old['id'] = 'node-002'
                blancctl.save(blancctl.NODES, [old])
                blancctl.save_text(blancctl.SUB, 'https://example.invalid/private\n')
                response = subprocess.CompletedProcess([], 0, stdout=(
                    'vless://12345678-1234-1234-1234-123456789abc@a.example:443'
                    '?security=reality#Extra, Germany\ntrojan://unsupported\n').encode(), stderr=b'')
                with mock.patch.object(blancctl.socket, 'create_connection', side_effect=OSError), \
                     mock.patch.object(blancctl.subprocess, 'run', return_value=response), \
                     contextlib.redirect_stdout(io.StringIO()):
                    merged = blancctl.update()
                self.assertEqual(len(merged), 2)
                self.assertTrue(merged[1]['stale'])
                self.assertEqual(len(blancctl.load(blancctl.NODES, [])), 1)
                self.assertEqual(len(blancctl.load(blancctl.RETAINED, [])), 1)
                self.assertEqual(blancctl.RETAINED.stat().st_mode & 0o777, 0o600)
                self.assertEqual(blancctl.SUB.read_text().strip(), 'https://example.invalid/private')
                self.assertEqual(blancctl.NODES.stat().st_mode & 0o777, 0o600)
                self.assertIn('trojan://unsupported', blancctl.RAW.read_text())
                self.assertEqual(blancctl.RAW.stat().st_mode & 0o777, 0o600)

    def test_best_uses_cache_without_a_separate_live_speedtest(self):
        node = sample('Extra, Germany', 'a.example')
        args = argparse.Namespace(refresh=False, workers=2, timeout=8)
        with mock.patch.object(blancctl, 'cached_nodes', return_value=([node], [])), \
             mock.patch.object(blancctl, 'load', return_value={}), \
             mock.patch.object(blancctl, 'update') as update, \
             mock.patch.object(blancctl, 'benchmark_choice', return_value=(node, {node['id']: 42})) as choice, \
             mock.patch.object(blancctl, 'select') as select, \
             mock.patch.object(blancctl, 'record_speed') as speed:
            blancctl.allbest(args)
        update.assert_not_called()
        speed.assert_not_called()
        choice.assert_called_once_with([node], 2, 8, [])
        select.assert_called_once_with(node, ping=42)
        self.assertTrue(args.refresh_after)

    def test_retained_servers_are_tested_if_current_profiles_fail(self):
        current = sample('Extra, Germany', 'a.example')
        older = sample('Extra, Turkey', 'b.example')
        older['id'] = 'node-002'
        older['stale'] = True
        first=({current['id']:None},{current['id']:[False]*4})
        second=({older['id']:55},{older['id']:[True]*4})
        with mock.patch.object(blancctl, 'benchmark', side_effect=[first,second]) as benchmark, \
             mock.patch.object(blancctl, 'load', return_value={}), \
             contextlib.redirect_stdout(io.StringIO()):
            selected, results = blancctl.benchmark_choice([current], 2, 8, [older])
        self.assertIs(selected, older)
        self.assertEqual(results[older['id']], 55)
        self.assertEqual(benchmark.call_args_list,[mock.call([current],2,8),mock.call([older],2,8)])

    def test_endpoint_variants_are_grouped_without_dropping_profiles(self):
        first=sample('A','a.example')
        second=sample('B','a.example')
        second['short_id']='other'
        third=sample('C','b.example')
        self.assertEqual([len(g) for g in blancctl.endpoint_groups([first,second,third])],[2,1])
        self.assertNotEqual(blancctl.node_key(first),blancctl.node_key(second))
        self.assertEqual(blancctl.diverse_candidates([first,second,third],2),[first,third])

    def test_russia_profiles_are_disabled_without_removing_other_countries(self):
        ru=sample('🇷🇺 Russia','ru.example')
        plain=sample('Extra, Russia','plain.example')
        other=sample('Extra, Belarus','by.example')
        self.assertTrue(blancctl.disabled_node(ru))
        self.assertTrue(blancctl.disabled_node(plain))
        self.assertFalse(blancctl.disabled_node(other))
        self.assertEqual(blancctl.selectable_nodes([ru,plain,other]),[other])

    def test_best_ignores_russia_in_current_backup_and_selected_profiles(self):
        ru=sample('🇷🇺 Russia','ru.example')
        other=sample('Extra, Germany','de.example'); other['id']='node-002'
        old_ru=sample('🇷🇺 Russia','old-ru.example'); old_ru['id']='old-ru'
        old_other=sample('Extra, Turkey','old-tr.example'); old_other['id']='old-tr'
        args=argparse.Namespace(refresh=False,workers=2,timeout=8)
        with mock.patch.object(blancctl,'cached_nodes',return_value=([ru,other],[old_ru,old_other])), \
             mock.patch.object(blancctl,'load',return_value={'id':'old-ru'}), \
             mock.patch.object(blancctl,'benchmark_choice',return_value=(other,{other['id']:42})) as choice, \
             mock.patch.object(blancctl,'select') as select:
            blancctl.allbest(args)
        choice.assert_called_once_with([other],2,8,[old_other])
        select.assert_called_once_with(other,ping=42)

    def test_russia_cannot_be_selected_explicitly_or_shown_in_countries(self):
        ru=sample('🇷🇺 Russia','ru.example')
        other=sample('Extra, Germany','de.example')
        with mock.patch.object(blancctl,'tun') as tun, \
             contextlib.redirect_stderr(io.StringIO()), \
             self.assertRaises(SystemExit):
            blancctl.select(ru)
        tun.assert_not_called()
        with mock.patch.object(blancctl,'cached_nodes',return_value=([ru,other],[])), \
             mock.patch.object(blancctl,'benchmark_choice') as choice, \
             contextlib.redirect_stderr(io.StringIO()), \
             self.assertRaises(SystemExit):
            blancctl.bycountry(argparse.Namespace(country='RU',workers=2,timeout=8))
        choice.assert_not_called()
        output=io.StringIO()
        with mock.patch.object(blancctl,'nodes',return_value=[ru,other]), \
             contextlib.redirect_stdout(output):
            blancctl.countries(None)
        self.assertIn('Germany',output.getvalue())
        self.assertNotIn('Russia',output.getvalue())

    def test_start_does_not_restart_saved_russia_connection(self):
        ru=sample('🇷🇺 Russia','ru.example')
        other=sample('Extra, Germany','de.example'); other['id']='node-002'
        with mock.patch.object(blancctl,'cached_nodes',return_value=([ru,other],[])), \
             mock.patch.object(blancctl,'load',return_value={
                 'id':ru['id'],'country_code':'RU','country':'Russia'}), \
             mock.patch.object(blancctl,'select') as select, \
             mock.patch.object(blancctl,'service') as service:
            blancctl.start(None)
        select.assert_called_once_with(other)
        service.assert_not_called()

    def test_failover_never_probes_russia_candidates(self):
        ru=sample('🇷🇺 Russia','ru.example')
        other=sample('Extra, Germany','de.example'); other['id']='node-002'
        with mock.patch.object(blancctl.subprocess,'run',return_value=subprocess.CompletedProcess([],0)), \
             mock.patch.object(blancctl,'try_operation_lock',side_effect=lambda:contextlib.nullcontext(True)), \
             mock.patch.object(blancctl,'cached_nodes',return_value=([ru,other],[])), \
             mock.patch.object(blancctl,'pingtest',return_value=None), \
             mock.patch.object(blancctl,'load',return_value={}), \
             mock.patch.object(blancctl,'save'), \
             mock.patch.object(blancctl,'test',return_value=(other['id'],50,[50]*4)) as probe, \
             mock.patch.object(blancctl,'select') as select, \
             mock.patch.dict(blancctl.os.environ,{'BLANCCTL_FAILOVER_FAILURES':'1'}), \
             contextlib.redirect_stdout(io.StringIO()):
            blancctl.failover(None)
        probe.assert_called_once()
        self.assertIs(probe.call_args.args[0],other)
        select.assert_called_once_with(other,ping=50)

    def test_failover_replaces_a_healthy_but_disabled_russia_selection(self):
        ru=sample('🇷🇺 Russia','ru.example')
        other=sample('Extra, Germany','de.example'); other['id']='node-002'
        def state(path,default):
            return {'id':ru['id'],'country_code':'RU','country':'Russia'} if path==blancctl.PICK else default
        with mock.patch.object(blancctl.subprocess,'run',return_value=subprocess.CompletedProcess([],0)), \
             mock.patch.object(blancctl,'try_operation_lock',side_effect=lambda:contextlib.nullcontext(True)), \
             mock.patch.object(blancctl,'cached_nodes',return_value=([ru,other],[])), \
             mock.patch.object(blancctl,'pingtest',return_value=100) as pingtest, \
             mock.patch.object(blancctl,'load',side_effect=state), \
             mock.patch.object(blancctl,'save'), \
             mock.patch.object(blancctl,'test',return_value=(other['id'],50,[50]*4)), \
             mock.patch.object(blancctl,'select') as select, \
             contextlib.redirect_stdout(io.StringIO()):
            blancctl.failover(None)
        pingtest.assert_not_called()
        select.assert_called_once_with(other,ping=50)

    def test_failover_keeps_a_deliberately_stopped_service_off(self):
        def systemctl(args, **_):
            return subprocess.CompletedProcess(args, 3)
        with mock.patch.object(blancctl.subprocess, 'run', side_effect=systemctl), \
             mock.patch.object(blancctl, 'service') as service, \
             mock.patch.object(blancctl, 'test') as probe, \
             contextlib.redirect_stdout(io.StringIO()):
            blancctl.failover(None)
        service.assert_not_called()
        probe.assert_not_called()

    def test_failover_restarts_failed_service_without_switching_a_healthy_node(self):
        calls=[]
        def systemctl(args, **_):
            calls.append(args[1])
            return subprocess.CompletedProcess(args, 3 if args[1]=='is-active' and calls.count('is-active')==1 else 0)
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(blancctl, 'FAILOVER', pathlib.Path(tmp)/'failover.json'), \
                 mock.patch.object(blancctl.subprocess, 'run', side_effect=systemctl), \
                 mock.patch.object(blancctl, 'try_operation_lock', side_effect=lambda:contextlib.nullcontext(True)), \
                 mock.patch.object(blancctl, 'service') as service, \
                 mock.patch.object(blancctl, 'pingtest', return_value=80), \
                 mock.patch.object(blancctl, 'routes_healthy', return_value=True), \
                 mock.patch.object(blancctl, 'select') as select, \
                 contextlib.redirect_stdout(io.StringIO()):
                blancctl.failover(None)
                self.assertEqual(blancctl.load(blancctl.FAILOVER,{})['failures'],0)
        service.assert_called_once_with('restart')
        select.assert_not_called()

    def test_failover_probes_alternatives_in_parallel_and_prefers_site_coverage(self):
        a=sample('A','a.example')
        b=sample('B','b.example'); b['id']='node-002'
        barrier=threading.Barrier(2)
        def probe(node, timeout, urls):
            barrier.wait(timeout=2)
            sites=[90,None,None,None] if node is a else [110,110,110,110]
            return node['id'],90 if node is a else 110,sites
        with mock.patch.object(blancctl.subprocess,'run',return_value=subprocess.CompletedProcess([],0)), \
             mock.patch.object(blancctl,'try_operation_lock',side_effect=lambda:contextlib.nullcontext(True)), \
             mock.patch.object(blancctl,'cached_nodes',return_value=([a,b],[])), \
             mock.patch.object(blancctl,'pingtest',return_value=None), \
             mock.patch.object(blancctl,'load',return_value={}), \
             mock.patch.object(blancctl,'save'), \
             mock.patch.object(blancctl,'test',side_effect=probe) as test, \
             mock.patch.object(blancctl,'select') as select, \
             mock.patch.dict(blancctl.os.environ,{'BLANCCTL_FAILOVER_FAILURES':'1'}), \
             contextlib.redirect_stdout(io.StringIO()):
            blancctl.failover(None)
        self.assertEqual(test.call_count,2)
        select.assert_called_once_with(b,ping=110)

    def test_failover_repairs_missing_tun_route_without_switching_nodes(self):
        with mock.patch.object(blancctl.subprocess,'run',return_value=subprocess.CompletedProcess([],0)), \
             mock.patch.object(blancctl,'try_operation_lock',side_effect=lambda:contextlib.nullcontext(True)), \
             mock.patch.object(blancctl,'load',return_value={}), \
             mock.patch.object(blancctl,'save'), \
             mock.patch.object(blancctl,'pingtest',return_value=90) as pingtest, \
             mock.patch.object(blancctl,'routes_healthy',side_effect=[False,True]) as routes, \
             mock.patch.object(blancctl,'service') as service, \
             mock.patch.object(blancctl,'select') as select, \
             contextlib.redirect_stdout(io.StringIO()):
            blancctl.failover(None)
        self.assertEqual(routes.call_count,2)
        self.assertEqual(pingtest.call_count,2)
        service.assert_called_once_with('restart')
        select.assert_not_called()

    def test_tun_route_repair_has_a_cooldown(self):
        recent={'route_repair_at':int(blancctl.time.time()),'failures':0}
        with mock.patch.object(blancctl.subprocess,'run',return_value=subprocess.CompletedProcess([],0)), \
             mock.patch.object(blancctl,'try_operation_lock',side_effect=lambda:contextlib.nullcontext(True)), \
             mock.patch.object(blancctl,'load',return_value=recent), \
             mock.patch.object(blancctl,'pingtest',return_value=90), \
             mock.patch.object(blancctl,'routes_healthy',return_value=False), \
             mock.patch.object(blancctl,'service') as service, \
             contextlib.redirect_stdout(io.StringIO()):
            blancctl.failover(None)
        service.assert_not_called()

    def test_tun_route_health_checks_both_policy_rules_and_routes(self):
        def ip(args, **_):
            value='1042: from all lookup 4269\n' if args[2]=='rule' else 'default dev blanc0 scope link\n'
            return subprocess.CompletedProcess(args,0,stdout=value)
        with mock.patch.object(blancctl.pathlib.Path,'exists',return_value=True), \
             mock.patch.object(blancctl.subprocess,'run',side_effect=ip) as run:
            self.assertTrue(blancctl.routes_healthy())
        self.assertEqual(run.call_count,4)

    def test_benchmark_prints_one_result_per_endpoint_but_tests_all_variants(self):
        first=sample('A','a.example')
        second=sample('B','a.example'); second['id']='node-002'; second['short_id']='other'
        third=sample('C','b.example'); third['id']='node-003'
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            output=io.StringIO()
            with mock.patch.multiple(blancctl,PINGS=root/'pings.json',HISTORY=root/'history.json',
                                     SITES=root/'sites.json'), \
                 mock.patch.object(blancctl,'physical_interface',return_value='wlan0'), \
                 mock.patch.object(blancctl,'test',side_effect=lambda n,*args:
                                   (n['id'],100,[100]*4)) as probe, \
                 contextlib.redirect_stdout(output):
                blancctl.benchmark([first,second,third],3,8)
        self.assertEqual(probe.call_count,3)
        self.assertEqual(sum('profiles):' in line for line in output.getvalue().splitlines()),2)

    def test_legacy_stale_records_are_not_active_but_remain_backups(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            current=sample('A','a.example')
            old=sample('B','b.example'); old['stale']=True
            with mock.patch.multiple(blancctl,NODES=root/'nodes.json',RETAINED=root/'retained.json',
                                     PICK=root/'selected.json'):
                blancctl.save(blancctl.NODES,[current,old])
                active,backups=blancctl.cached_nodes()
                self.assertEqual(active,[current])
                self.assertEqual(backups,[old])
                self.assertEqual(blancctl.nodes(),[current])

    def test_refresh_keeps_rotating_variants_without_multiplying_active_nodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            old=sample('A','a.example'); old['sni']='first.example'
            old['id']='original-id'
            def response(sni):
                line=('vless://12345678-1234-1234-1234-123456789abc@a.example:443'
                      f'?security=reality&type=tcp&flow=xtls-rprx-vision&sni={sni}#A')
                return subprocess.CompletedProcess([],0,stdout=line.encode(),stderr=b'')
            with mock.patch.multiple(blancctl,STATE=root,SUB=root/'subscription.url',
                                     NODES=root/'nodes.json',RETAINED=root/'retained.json',
                                     RAW=root/'subscription.raw',PICK=root/'selected.json',
                                     DOWNLOAD=root/'download.json'):
                blancctl.save(blancctl.NODES,[old])
                blancctl.save(blancctl.PICK,{'id':'original-id'})
                blancctl.save_text(blancctl.SUB,'https://example.invalid/private\n')
                with mock.patch.object(blancctl.socket,'create_connection',side_effect=OSError), \
                     mock.patch.object(blancctl.subprocess,'run',side_effect=[response('second.example'),
                                                                             response('third.example'),
                                                                             response('first.example')]), \
                     contextlib.redirect_stdout(io.StringIO()):
                    for active_count,backup_count in ((1,1),(1,2),(1,2)):
                        blancctl.update()
                        current,backup=blancctl.cached_nodes()
                        self.assertEqual((len(current),len(backup)),(active_count,backup_count))
                        self.assertEqual(len(blancctl.load(blancctl.NODES,[])),1)
                self.assertEqual(current[0]['id'],'original-id')
                self.assertEqual(len({blancctl.node_key(n) for n in current+backup}),3)

    def test_best_uses_site_coverage_without_rejecting_partially_working_nodes(self):
        a=sample('A', 'a.example')
        b=sample('B', 'b.example')
        b['id']='node-002'
        results={a['id']:50,b['id']:100}
        sites={a['id']:[True,False,False,True],b['id']:[True]*4}
        self.assertIs(blancctl.best([a,b],results,sites),b)
        self.assertIs(blancctl.best([a,b],{a['id']:50,b['id']:None},sites),a)
        sites[a['id']]=[True]*4
        self.assertIs(blancctl.best([a,b],{a['id']:110,b['id']:100},sites,a['id']),a)

    def test_best_uses_speed_only_for_comparable_responsive_nodes(self):
        a=sample('Low ping', 'a.example')
        b=sample('Fast download', 'b.example'); b['id']='node-002'
        coverage={a['id']:[True]*4,b['id']:[True]*4}
        pings={a['id']:100,b['id']:120}
        self.assertIs(blancctl.best([a,b],pings,coverage,speeds={a['id']:10,b['id']:20}),b)
        self.assertIs(blancctl.best([a,b],pings,coverage,a['id'],{a['id']:10,b['id']:20}),b)
        self.assertIs(blancctl.best([a,b],pings,coverage,a['id'],{a['id']:10,b['id']:12}),a)
        self.assertIs(blancctl.best([a,b],pings,coverage,speeds={b['id']:100}),a)
        coverage[b['id']]=[True,False,False,False]
        self.assertIs(blancctl.best([a,b],pings,coverage,speeds={a['id']:10,b['id']:100}),a)
        coverage[b['id']]=[True]*4
        pings[b['id']]=500
        self.assertIs(blancctl.best([a,b],pings,coverage,speeds={a['id']:10,b['id']:100}),a)

    def test_speed_stage_only_checks_nearby_working_profiles_in_parallel(self):
        a=sample('A', 'a.example')
        b=sample('B', 'b.example'); b['id']='node-002'
        failed=sample('Failed', 'c.example'); failed['id']='node-003'
        partial=sample('Partial', 'd.example'); partial['id']='node-004'
        pings={a['id']:100,b['id']:120,failed['id']:None,partial['id']:50}
        sites={a['id']:[True]*4,b['id']:[True]*4,partial['id']:[True,False,False,False]}
        barrier=threading.Barrier(2)
        def measure(node, timeout, interface):
            barrier.wait(timeout=2)
            self.assertEqual((timeout,interface),(4.0,'wlan0'))
            return 10 if node is a else 20
        with mock.patch.object(blancctl,'physical_interface',return_value='wlan0'), \
             mock.patch.object(blancctl,'speedtest_node',side_effect=measure) as speedtest, \
             contextlib.redirect_stdout(io.StringIO()):
            speeds=blancctl.benchmark_speeds([a,b,failed,partial],pings,sites,None,4,8)
        self.assertEqual(speeds,{a['id']:10,b['id']:20})
        self.assertEqual(speedtest.call_count,2)

    def test_speed_stage_skips_when_there_is_nothing_to_compare(self):
        working=sample('Working','a.example')
        failed=sample('Failed','b.example'); failed['id']='node-002'
        with mock.patch.object(blancctl,'speedtest_node') as speedtest:
            speeds=blancctl.benchmark_speeds([working,failed],
              {working['id']:100,failed['id']:None},{working['id']:[True]*4},None,4,8)
        self.assertEqual(speeds,{})
        speedtest.assert_not_called()

    def test_benchmark_choice_checks_ping_before_speed(self):
        a=sample('A','a.example')
        b=sample('B','b.example'); b['id']='node-002'
        events=[]
        def ping(*_):
            events.append('ping')
            return {a['id']:100,b['id']:120},{a['id']:[True]*4,b['id']:[True]*4}
        def speed(*_):
            events.append('speed')
            return {a['id']:10,b['id']:20}
        with mock.patch.object(blancctl,'benchmark',side_effect=ping), \
             mock.patch.object(blancctl,'benchmark_speeds',side_effect=speed), \
             mock.patch.object(blancctl,'load',return_value={}):
            winner,_=blancctl.benchmark_choice([a,b],4,8)
        self.assertEqual(events,['ping','speed'])
        self.assertIs(winner,b)

    def test_node_speed_test_accepts_partial_download_but_not_failed_endpoint(self):
        node=sample('Working','a.example')
        with mock.patch.object(blancctl,'node_proxy',return_value=contextlib.nullcontext('socks5h://127.0.0.1:1234')), \
             mock.patch.object(blancctl.subprocess,'run',return_value=subprocess.CompletedProcess(
                 [],28,stdout='131072 4.0 0.5 200')) as curl:
            speed=blancctl.speedtest_node(node,4,'wlan0')
        self.assertEqual(speed,0.3)
        self.assertIn('--proxy',curl.call_args.args[0])
        with mock.patch.object(blancctl,'node_proxy',return_value=contextlib.nullcontext('socks5h://127.0.0.1:1234')), \
             mock.patch.object(blancctl.subprocess,'run',return_value=subprocess.CompletedProcess(
                 [],0,stdout='524288 1.0 0.5 503')):
            self.assertIsNone(blancctl.speedtest_node(node,4,'wlan0'))

    def test_failed_new_subscription_keeps_existing_cache_and_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with mock.patch.multiple(blancctl, STATE=root, SUB=root/'subscription.url',
                                     NODES=root/'nodes.json', DOWNLOAD=root/'download.json',
                                     PICK=root/'selected.json'):
                old = sample('Extra, Turkey', 'b.example')
                blancctl.save(blancctl.NODES, [old])
                blancctl.save_text(blancctl.SUB, 'https://example.invalid/old\n')
                failure = subprocess.CompletedProcess([], 22, stdout=b'', stderr=b'HTTP 403')
                with mock.patch.object(blancctl.socket, 'create_connection', side_effect=OSError), \
                     mock.patch.object(blancctl.subprocess, 'run', return_value=failure), \
                     contextlib.redirect_stderr(io.StringIO()), \
                     self.assertRaises(SystemExit):
                    blancctl.update(url='https://example.invalid/new', replace=True)
                self.assertEqual(blancctl.SUB.read_text().strip(), 'https://example.invalid/old')
                self.assertEqual(blancctl.load(blancctl.NODES, []), [old])

    def test_four_sites_run_in_parallel_and_failures_are_recorded(self):
        response = subprocess.CompletedProcess([], 0, stdout=(
            '0 204 0.1\n1 200 0.2\n2 403 0.3\n3 200 0.4\n'), stderr='')
        with mock.patch.object(blancctl.subprocess, 'run', return_value=response) as run:
            values = blancctl.probe_urls('socks5h://127.0.0.1:12345',
                                         blancctl.TEST_URLS, 4)
        self.assertEqual(len(blancctl.TEST_URLS), 4)
        self.assertIn('--parallel', run.call_args.args[0])
        self.assertIn('--range', run.call_args.args[0])
        self.assertEqual(run.call_args.args[0][run.call_args.args[0].index('--parallel-max')+1], '4')
        self.assertIsNone(values[2])
        self.assertEqual(blancctl.probe_score(values), 200)
        self.assertEqual(blancctl.probe_score([100, 200, 300, 400]), 250)
        blancctl.log_event.assert_any_call('curl_probe',status='ok',exit_code=0,
                                           http_codes='204-200-403-200',sites=4)

    def test_live_health_accepts_any_successful_site(self):
        with mock.patch.object(blancctl, 'probe_urls', return_value=[None, 230, None, None]):
            self.assertEqual(blancctl.pingtest(5), 230)
        with mock.patch.object(blancctl, 'probe_urls', return_value=[None]*4):
            self.assertIsNone(blancctl.pingtest(5))

    def test_vless_vision_does_not_block_udp_443_and_tun_proxies_public_ips(self):
        node = sample('Extra, Germany', 'a.example')
        with mock.patch.object(blancctl, 'physical_interface', return_value='wlan0'):
            config = blancctl.tun(node)
        self.assertNotIn('mux', config['outbounds'][0])
        self.assertTrue(config['inbounds'][0]['sniffing']['enabled'])
        self.assertTrue(config['inbounds'][0]['sniffing']['routeOnly'])
        self.assertEqual(config['routing']['rules'][0]['ip'], ['geoip:private'])
        self.assertNotIn('geoip:ru', str(config['routing']))
        self.assertNotIn('ru|xn--p1ai', str(config['routing']))

    def test_xhttp_link_preserves_mode_extra_and_download_interface(self):
        extra='{"downloadSettings":{"address":"download.example","port":443,"network":"xhttp","xhttpSettings":{"path":"/down"}}}'
        node = blancctl.parse(
            'vless://12345678-1234-1234-1234-123456789abc@upload.example:443'
            '?security=tls&type=xhttp&path=%2Fup&host=front.example&mode=stream-up'
            '&alpn=h2%2Chttp%2F1.1&extra='+urllib.parse.quote(extra), 0)
        stream = blancctl.outbound(node, 'wlan0')['streamSettings']
        self.assertEqual(stream['xhttpSettings']['path'], '/up')
        self.assertEqual(stream['xhttpSettings']['host'], 'front.example')
        self.assertEqual(stream['xhttpSettings']['mode'], 'stream-up')
        self.assertEqual(stream['xhttpSettings']['extra']['downloadSettings']['sockopt']['interface'], 'wlan0')
        self.assertEqual(stream['tlsSettings']['alpn'], ['h2', 'http/1.1'])

    def test_grpc_and_httpupgrade_link_settings_are_not_lost(self):
        base='vless://12345678-1234-1234-1234-123456789abc@a.example:443?security=tls'
        grpc=blancctl.parse(base+'&type=grpc&serviceName=myservice&authority=grpc.example', 0)
        upgrade=blancctl.parse(base+'&type=httpupgrade&path=%2Fapi&host=front.example', 1)
        self.assertEqual(blancctl.outbound(grpc)['streamSettings']['grpcSettings'],
                         {'serviceName':'myservice','authority':'grpc.example'})
        self.assertEqual(blancctl.outbound(upgrade)['streamSettings']['httpupgradeSettings'],
                         {'path':'/api','host':'front.example'})

    def test_unsupported_vless_transport_is_rejected_instead_of_misconfigured(self):
        with self.assertRaises(ValueError):
            blancctl.parse('vless://12345678-1234-1234-1234-123456789abc@a.example:443?type=unknown', 0)

    @unittest.skipUnless(shutil.which('xray'), 'Xray is not installed')
    def test_generated_transport_configs_pass_xray_validation(self):
        base='vless://12345678-1234-1234-1234-123456789abc@a.example:443?security=tls'
        links=(base+'&type=xhttp&path=%2Fup&mode=stream-up&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%7D',
               base+'&type=grpc&serviceName=myservice',
               base+'&type=httpupgrade&path=%2Fapi&host=front.example')
        with tempfile.TemporaryDirectory() as tmp:
            config=pathlib.Path(tmp)/'test.json'
            for index,link in enumerate(links):
                node=blancctl.parse(link,index)
                config.write_text(json.dumps(blancctl.socks(node,18080,'wlan0')))
                result=subprocess.run(['xray','run','-test','-c',str(config)],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)

    @unittest.skipUnless(shutil.which('xray'), 'Xray is not installed')
    def test_generated_tun_config_passes_xray_validation(self):
        node=blancctl.parse(
            'vless://12345678-1234-1234-1234-123456789abc@a.example:443?security=tls&type=ws',0)
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(blancctl, 'physical_interface', return_value='wlan0'):
            config=pathlib.Path(tmp)/'tun.json'
            generated=blancctl.tun(node)
            # Xray -test opens a real TUN device, so validate the same stream,
            # sniffing and routing with a non-privileged SOCKS inbound.
            generated['inbounds']=[{'listen':'127.0.0.1','port':18080,'protocol':'socks',
                                    'settings':{'udp':True},'sniffing':generated['inbounds'][0]['sniffing']}]
            config.write_text(json.dumps(generated))
            result=subprocess.run(['xray','run','-test','-c',str(config)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_plain_update_never_switches_the_live_connection(self):
        node = sample('Same name', 'new.example')
        with mock.patch.object(blancctl, 'update', return_value=[node]), \
             mock.patch.object(blancctl, 'load', return_value={'id':'old-id'}), \
             mock.patch.object(blancctl, 'select') as select, \
             contextlib.redirect_stdout(io.StringIO()):
            blancctl.refresh(None)
        select.assert_not_called()

    def test_start_uses_saved_config_if_selected_node_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            config=root/'xray.json'
            blancctl.save(config, {'old':'working'})
            with mock.patch.object(blancctl, 'CONF', config), \
                 mock.patch.object(blancctl, 'load',
                                   side_effect=lambda path, default: {'id':'old-id'} if path==blancctl.PICK else []), \
                 mock.patch.object(blancctl, 'service') as service, \
                 mock.patch.object(blancctl, 'select') as select, \
                 mock.patch.object(blancctl, 'update') as update, \
                 contextlib.redirect_stdout(io.StringIO()):
                blancctl.start(None)
        service.assert_called_once_with('restart')
        select.assert_not_called()
        update.assert_not_called()

    def test_failed_new_connection_restores_prior_selection(self):
        old = sample('Old', 'old.example')
        new = sample('New', 'new.example')
        new['id'] = 'node-002'
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with mock.patch.multiple(blancctl, CONF=root/'xray.json', PICK=root/'selected.json',
                                     STATS=root/'stats.json'), \
                 mock.patch.object(blancctl, 'tun', return_value={
                     'outbounds':['new'],'inbounds':[{'sniffing':{'enabled':True}}]}), \
                 mock.patch.object(blancctl, 'port', return_value=12345), \
                 mock.patch.object(blancctl.subprocess, 'run',
                                   return_value=subprocess.CompletedProcess([], 0)), \
                 mock.patch.object(blancctl, 'service') as service, \
                 mock.patch.object(blancctl, 'pingtest', return_value=None), \
                 mock.patch.dict(blancctl.os.environ, {'BLANCCTL_NO_SERVICE':'0'}), \
                 contextlib.redirect_stderr(io.StringIO()), \
                 self.assertRaises(SystemExit):
                blancctl.save(blancctl.CONF, {'outbounds':['old']})
                blancctl.save(blancctl.PICK, {'id':old['id']})
                blancctl.save(blancctl.STATS, {'ping_ms':10})
                blancctl.select(new)
            self.assertEqual(blancctl.load(root/'xray.json', {}), {'outbounds':['old']})
            self.assertEqual(blancctl.load(root/'selected.json', {})['id'], old['id'])
            self.assertEqual(blancctl.load(root/'stats.json', {})['ping_ms'], 10)
            self.assertEqual(service.call_count, 2)

    def test_reselecting_healthy_same_config_does_not_restart(self):
        node=sample('Same', 'a.example')
        config={'outbounds':['unchanged']}
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            with mock.patch.multiple(blancctl, CONF=root/'xray.json', PICK=root/'selected.json',
                                     STATS=root/'stats.json'), \
                 mock.patch.object(blancctl, 'tun', return_value=config), \
                 mock.patch.object(blancctl.subprocess, 'run',
                                   return_value=subprocess.CompletedProcess([],0)), \
                 mock.patch.object(blancctl, 'service') as service, \
                 mock.patch.object(blancctl, 'pingtest') as pingtest, \
                 contextlib.redirect_stdout(io.StringIO()):
                blancctl.save(blancctl.CONF,config)
                blancctl.save(blancctl.PICK,{'id':node['id']})
                blancctl.select(node)
        service.assert_not_called()
        pingtest.assert_not_called()

    def test_failed_probe_keeps_last_success_for_future_timeout(self):
        node = sample('Extra, Germany', 'a.example')
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with mock.patch.multiple(blancctl, PINGS=root/'latencies.json',
                                     HISTORY=root/'history.json', SITES=root/'sites.json'):
                blancctl.save(blancctl.PINGS, {node['id']: None})
                blancctl.save(blancctl.HISTORY, {node['id']: 4000})
                with mock.patch.object(blancctl, 'physical_interface', return_value='wlan0'), \
                     mock.patch.object(blancctl, 'test', return_value=(node['id'], None, [None]*4)) as probe, \
                     contextlib.redirect_stdout(io.StringIO()):
                    result,sites = blancctl.benchmark([node], 1, 8)
                self.assertIsNone(result[node['id']])
                self.assertEqual(sites[node['id']], [False]*4)
                self.assertEqual(probe.call_args_list[0].args[1], 8)
                self.assertEqual(blancctl.load(blancctl.HISTORY, {})[node['id']], 4000)

    def test_adaptive_limits(self):
        self.assertEqual(blancctl.adaptive_timeout(None, 8), 5.5)
        self.assertEqual(blancctl.adaptive_timeout(500, 8), 3.0)
        self.assertEqual(blancctl.adaptive_timeout(4000, 8), 8)

    def test_best_starts_background_refresh_after_releasing_lock(self):
        events = []

        @contextlib.contextmanager
        def lock():
            events.append('locked')
            yield
            events.append('unlocked')

        def choose(args):
            events.append('selected')
            args.refresh_after = True

        with mock.patch.object(blancctl.sys, 'argv', ['blancctl', 'best']), \
             mock.patch.object(blancctl, 'operation_lock', lock), \
             mock.patch.object(blancctl, 'allbest', choose), \
             mock.patch.object(blancctl, 'background_refresh', lambda: events.append('refresh')):
            blancctl.main()
        self.assertEqual(events, ['locked', 'selected', 'unlocked', 'refresh'])

    def test_failed_best_still_starts_refresh_after_releasing_lock(self):
        events = []

        @contextlib.contextmanager
        def lock():
            try: yield
            finally: events.append('unlocked')

        def choose(args):
            args.refresh_after = True
            raise SystemExit(1)

        with mock.patch.object(blancctl.sys, 'argv', ['blancctl', 'best']), \
             mock.patch.object(blancctl, 'operation_lock', lock), \
             mock.patch.object(blancctl, 'allbest', choose), \
             mock.patch.object(blancctl, 'background_refresh', lambda: events.append('refresh')), \
             self.assertRaises(SystemExit):
            blancctl.main()
        self.assertEqual(events, ['unlocked', 'refresh'])

    def test_background_refresh_records_result(self):
        node = sample('Extra, Germany', 'a.example')
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with mock.patch.multiple(blancctl, STATE=root, LOCK=root/'operation.lock',
                                     REFRESH_STATUS=root/'subscription-refresh.json'), \
                 mock.patch.object(blancctl, 'update', return_value=[node]), \
                 contextlib.redirect_stdout(io.StringIO()):
                blancctl.refresh_cache(None)
                status = blancctl.load(blancctl.REFRESH_STATUS, {})
        self.assertEqual(status['state'], 'completed')
        self.assertEqual((status['current'], status['retained']), (1, 0))

    def test_background_refresh_waits_for_configuration_lock(self):
        node = sample('Extra, Germany', 'a.example')
        attempts = []

        @contextlib.contextmanager
        def lock():
            attempts.append(True)
            yield len(attempts) > 1

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with mock.patch.multiple(blancctl, STATE=root, REFRESH_STATUS=root/'subscription-refresh.json'), \
                 mock.patch.object(blancctl, 'try_operation_lock', lock), \
                 mock.patch.object(blancctl.time, 'sleep') as sleep, \
                 mock.patch.object(blancctl, 'update', return_value=[node]), \
                 contextlib.redirect_stdout(io.StringIO()):
                blancctl.refresh_cache(None)
                status = blancctl.load(blancctl.REFRESH_STATUS, {})
        self.assertEqual(len(attempts), 2)
        sleep.assert_called_once_with(.25)
        self.assertEqual(status['state'], 'completed')

    def test_background_refresh_reports_unexpected_failure_without_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with mock.patch.multiple(blancctl, STATE=root, LOCK=root/'operation.lock',
                                     REFRESH_STATUS=root/'subscription-refresh.json'), \
                 mock.patch.object(blancctl, 'update', side_effect=RuntimeError('private URL')):
                blancctl.refresh_cache(None)
                status = blancctl.load(blancctl.REFRESH_STATUS, {})
        self.assertEqual(status['state'], 'failed')
        self.assertNotIn('private URL', str(status))

    def test_background_refresh_queues_one_detached_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            status_path = pathlib.Path(tmp)/'subscription-refresh.json'
            with mock.patch.object(blancctl, 'REFRESH_STATUS', status_path), \
                 mock.patch.object(blancctl.subprocess, 'Popen') as popen, \
                 contextlib.redirect_stdout(io.StringIO()):
                blancctl.background_refresh()
                blancctl.background_refresh()
            status = blancctl.load(status_path, {})
        self.assertEqual(status['state'], 'queued')
        self.assertEqual(popen.call_count, 1)
        self.assertEqual(popen.call_args.kwargs['start_new_session'], True)
        self.assertEqual(popen.call_args.args[0][-1], 'refresh-cache')

    def test_node_checks_overlap(self):
        a = sample('Extra, Germany', 'a.example')
        b = sample('Extra, Turkey', 'b.example')
        b['id'] = 'node-002'
        barrier = threading.Barrier(2)

        def probe(node, timeout, interface):
            barrier.wait(timeout=2)
            return node['id'], 100, [100]*4

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with mock.patch.multiple(blancctl, PINGS=root/'latencies.json',
                                     HISTORY=root/'history.json', SITES=root/'sites.json'), \
                 mock.patch.object(blancctl, 'physical_interface', return_value='wlan0'), \
                 mock.patch.object(blancctl, 'test', side_effect=probe), \
                 contextlib.redirect_stdout(io.StringIO()):
                result,sites = blancctl.benchmark([a, b], 2, 8)
        self.assertEqual((result[a['id']], result[b['id']]), (100, 100))
        self.assertEqual(sites[a['id']], [True]*4)


class DiagnosticLogTests(unittest.TestCase):
    def test_private_rotating_log_redacts_urls_and_exception_messages(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(blancctl,'STATE',pathlib.Path(tmp)), \
             mock.patch.object(blancctl,'LOG_LIMIT',260), \
             mock.patch.object(blancctl,'LOG_BACKUPS',2):
            for number in range(12):
                blancctl.log_event('test_probe',node_id='node-001',sequence=number,
                                   secret='vless://uuid@private.example?token=secret')
            try: raise RuntimeError('https://private.example/sub?token=secret')
            except RuntimeError as exc: blancctl.log_exception('test_error',exc)
            path=blancctl.diagnostic_log_path()
            files=[path,path.with_name(path.name+'.1'),path.with_name(path.name+'.2')]
            self.assertTrue(all(p.exists() for p in files))
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertEqual((path.parent/'events.lock').stat().st_mode & 0o777,0o600)
            data=''.join(p.read_text() for p in files)
            self.assertIn('redacted',data)
            self.assertIn('test_error',data)
            self.assertNotIn('private.example',data)
            self.assertNotIn('token=secret',data)
            self.assertTrue(all(json.loads(line)['event'] for line in data.splitlines()))

    def test_log_command_reads_rotated_history_without_service_access(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(blancctl,'STATE',pathlib.Path(tmp)), \
             mock.patch.object(blancctl,'LOG_LIMIT',220), \
             mock.patch.object(blancctl,'LOG_BACKUPS',2):
            for number in range(5): blancctl.log_event('check',sequence=number)
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                blancctl.logs(argparse.Namespace(lines=3,service=False))
            lines=[json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual([line['sequence'] for line in lines],[2,3,4])

    def test_log_write_failure_does_not_mask_operation(self):
        with tempfile.TemporaryDirectory() as tmp:
            invalid=pathlib.Path(tmp)/'not-a-directory'
            invalid.write_text('occupied')
            errors=io.StringIO()
            with mock.patch.object(blancctl,'STATE',invalid), contextlib.redirect_stderr(errors):
                blancctl.log_event('test')
            self.assertIn('diagnostic logging unavailable',errors.getvalue())


if __name__ == '__main__':
    unittest.main()
