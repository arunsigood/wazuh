# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import subprocess
import time
import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, callback_audit_added_rule,
                               callback_audit_connection,
                               callback_audit_health_check,
                               callback_audit_loaded_rule,
                               callback_audit_reloaded_rule,
                               callback_audit_rules_manipulation,
                               callback_realtime_added_directory,
                               callback_audit_key, 
                               create_file,
                               delete_file,
                               REGULAR,
                               detect_initial_scan)
from wazuh_testing.tools import (FileMonitor, check_apply_test,
                                 load_wazuh_configurations,
                                 restart_wazuh_service,
                                 truncate_file)


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), os.path.join('/', 'testdir3')]
testdir1, testdir2, testdir3 = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

configurations = load_wazuh_configurations(configurations_path, __name__)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_audit_health_check(tags_to_apply, get_configuration,
                            configure_environment, restart_syscheckd):
    """Checks if the health check is passed."""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    wazuh_log_monitor.start(timeout=20, callback=callback_audit_health_check)


@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_added_rules(tags_to_apply, get_configuration,
                     configure_environment, restart_syscheckd):
    """Checks if the specified folders are added to Audit rules list."""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    events = wazuh_log_monitor.start(timeout=20,
                                     callback=callback_audit_added_rule,
                                     accum_results=3).result()

    assert (testdir1 in events)
    assert (testdir2 in events)
    assert (testdir3 in events)


@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_readded_rules(tags_to_apply, get_configuration,
                       configure_environment, restart_syscheckd):
    """Checks if the removed rules are added to Audit rules list."""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Remove added rules
    for dir in (testdir1, testdir2, testdir3):
        os.system("auditctl -W {0} -p wa -k wazuh_fim".format(dir))

        wazuh_log_monitor.start(timeout=20,
                                callback=callback_audit_rules_manipulation)

        events = wazuh_log_monitor.start(timeout=10,
                                         callback=callback_audit_reloaded_rule).result()

        assert (dir in events)


@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_readded_rules_on_restart(tags_to_apply, get_configuration,
                                  configure_environment, restart_syscheckd):
    """Checks if the rules are added to Audit when it restarts."""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Restart Audit
    p = subprocess.Popen(["service", "auditd", "restart"])
    p.wait()

    wazuh_log_monitor.start(timeout=10,
                            callback=callback_audit_connection)

    events = wazuh_log_monitor.start(timeout=30,
                                     callback=callback_audit_loaded_rule,
                                     accum_results=3).result()

    assert (testdir1 in events)
    assert (testdir2 in events)
    assert (testdir3 in events)


@pytest.mark.parametrize('tags_to_apply', [
    ({'config1'})
])
def test_move_rules_realtime(tags_to_apply, get_configuration,
                             configure_environment, restart_syscheckd):
    """Checks if the rules are changed to realtime when Audit stops."""
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Stop Audit
    p = subprocess.Popen(["service", "auditd", "stop"])
    p.wait()

    events = wazuh_log_monitor.start(timeout=30,
                                     callback=callback_realtime_added_directory,
                                     accum_results=3).result()

    assert (testdir1 in events)
    assert (testdir2 in events)
    assert (testdir3 in events)

    # Start Audit
    p = subprocess.Popen(["service", "auditd", "start"])
    p.wait()


def test_audit_key(get_configuration, configure_environment, restart_syscheckd):
    check_apply_test({"audit_key"}, get_configuration['tags'])
    
    audit_key = "custom_audit_key"
    audit_dir = "/testdir1"

    # Add watch rule
    os.system("auditctl -w " + audit_dir + " -p wa -k " + audit_key)

    truncate_file(LOG_FILE_PATH)

    restart_wazuh_service()

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    detect_initial_scan(wazuh_log_monitor)

    create_file(REGULAR, audit_dir, "testfile")

    events = wazuh_log_monitor.start(timeout=30,
                                     callback=callback_audit_key,
                                     accum_results=1).result()
    assert (audit_key in events)

    # Remove watch rule
    os.system("auditctl -W " + audit_dir + " -p wa -k " + audit_key)
