#!/bin/bash

set -e

ALLOY_VERSION="v1.4.3"

function check_and_install {
    if ! command -v $1 &> /dev/null; then
        echo "$1 is not found, installing..."
        sudo apt-get install -y $2 || sudo yum install -y $2
    else
        echo "$1 is already installed."
    fi
}

function create_alloy_user {
    if ! id "alloy" &>/dev/null; then
        echo "Creating alloy user..."
        sudo useradd --system --no-create-home alloy
    else
        echo "Alloy user already exists."
    fi
    sudo usermod -aG adm alloy
}

function install_alloy {
    echo "Checking dependencies..."
    check_and_install "wget" "wget"
    check_and_install "curl" "curl"
    check_and_install "zip" "zip"
    check_and_install "unzip" "unzip"

    echo "Updating package lists..."
    sudo apt update -y

    create_alloy_user

    HOSTNAME=$(hostname)
    PROMETHEUS_HOST="<PROMETHEUS_IP>"
    LOKI_HOST="<LOKI_IP>"

    echo "Downloading Grafana Alloy..."
    TEMP_DIR=$(mktemp -d -t alloy-setup-XXXX)
    wget -P "$TEMP_DIR" "https://github.com/grafana/alloy/releases/download/${ALLOY_VERSION}/alloy-linux-amd64.zip"
    unzip "$TEMP_DIR/alloy-linux-amd64.zip" -d "$TEMP_DIR"

    sudo mv "$TEMP_DIR/alloy-linux-amd64" /usr/local/bin/alloy
    sudo chmod 755 /usr/local/bin/alloy

    echo "Setting up configuration for Grafana Alloy..."
    sudo mkdir -p /etc/alloy
    sudo mkdir -p /var/lib/alloy

    sudo chown -R alloy:alloy /var/lib/alloy

    echo "Creating endpoints configuration..."
    sudo bash -c "cat << EOF > /etc/alloy/endpoints.json
{
    \"metrics\": {
        \"url\": \"http://${PROMETHEUS_HOST}:9009/api/v1/push\"
    },
    \"logs\": {
        \"url\": \"http://${LOKI_HOST}:3100/loki/api/v1/push\"
    }
}
EOF"

    echo "Creating Grafana Alloy main configuration file..."
    sudo bash -c "cat << EOF > /etc/alloy/config.alloy
local.file \"endpoints\" {
    filename = \"/etc/alloy/endpoints.json\"
}

prometheus.exporter.self \"integrations_alloy\" { }

discovery.relabel \"integrations_alloy\" {
  targets = prometheus.exporter.self.integrations_alloy.targets

  rule {
    target_label = \"instance\"
    replacement  = \"\${HOSTNAME}\"
  }

  rule {
    target_label = \"job\"
    replacement  = \"integrations/alloy\"
  }
}

prometheus.scrape \"integrations_alloy\" {
  targets    = discovery.relabel.integrations_alloy.output
  forward_to = [prometheus.relabel.integrations_alloy.receiver]

  scrape_interval = \"60s\"
}

prometheus.relabel \"integrations_alloy\" {
  forward_to = [prometheus.remote_write.mimir.receiver]

  rule {
    source_labels = [\"__name__\"]
    regex         = \"(prometheus_target_sync_length_seconds_sum|prometheus_target_scrapes_.*|prometheus_target_interval.*|prometheus_sd_discovered_targets|alloy_build.*|prometheus_remote_write_wal_samples_appended_total|process_start_time_seconds)\"
    action        = \"keep\"
  }
}

discovery.relabel \"integrations_node_exporter\" {
  targets = prometheus.exporter.unix.integrations_node_exporter.targets

  rule {
    target_label = \"instance\"
    replacement  = \"\${HOSTNAME}\"
  }

  rule {
    target_label = \"job\"
    replacement = \"integrations/node_exporter\"
  }
}

prometheus.exporter.unix \"integrations_node_exporter\" {
  disable_collectors = [\"ipvs\", \"btrfs\", \"infiniband\", \"xfs\", \"zfs\"]

  filesystem {
    fs_types_exclude     = \"^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|tmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs|tracefs)$\"
    mount_points_exclude = \"^/(dev|proc|run/credentials/.+|sys|var/lib/docker/.+)($|/)\"
    mount_timeout        = \"5s\"
  }

  netclass {
    ignored_devices = \"^(veth.*|cali.*|[a-f0-9]{15})$\"
  }

  netdev {
    device_exclude = \"^(veth.*|cali.*|[a-f0-9]{15})$\"
  }
}

prometheus.scrape \"integrations_node_exporter\" {
  targets    = discovery.relabel.integrations_node_exporter.output
  forward_to = [prometheus.relabel.integrations_node_exporter.receiver]
}

prometheus.relabel \"integrations_node_exporter\" {
  forward_to = [prometheus.remote_write.mimir.receiver]

  rule {
    source_labels = [\"__name__\"]
    regex         = \"up|node_arp_entries|node_boot_time_seconds|node_context_switches_total|node_cpu_seconds_total|node_disk_io_time_seconds_total|node_disk_io_time_weighted_seconds_total|node_disk_read_bytes_total|node_disk_read_time_seconds_total|node_disk_reads_completed_total|node_disk_write_time_seconds_total|node_disk_writes_completed_total|node_disk_written_bytes_total|node_filefd_allocated|node_filefd_maximum|node_filesystem_avail_bytes|node_filesystem_device_error|node_filesystem_files|node_filesystem_files_free|node_filesystem_readonly|node_filesystem_size_bytes|node_intr_total|node_load1|node_load15|node_load5|node_md_disks|node_md_disks_required|node_memory_Active_anon_bytes|node_memory_Active_bytes|node_memory_Active_file_bytes|node_memory_AnonHugePages_bytes|node_memory_AnonPages_bytes|node_memory_Bounce_bytes|node_memory_Buffers_bytes|node_memory_Cached_bytes|node_memory_CommitLimit_bytes|node_memory_Committed_AS_bytes|node_memory_DirectMap1G_bytes|node_memory_DirectMap2M_bytes|node_memory_DirectMap4k_bytes|node_memory_Dirty_bytes|node_memory_HugePages_Free|node_memory_HugePages_Rsvd|node_memory_HugePages_Surp|node_memory_HugePages_Total|node_memory_Hugepagesize_bytes|node_memory_Inactive_anon_bytes|node_memory_Inactive_bytes|node_memory_Inactive_file_bytes|node_memory_Mapped_bytes|node_memory_MemAvailable_bytes|node_memory_MemFree_bytes|node_memory_MemTotal_bytes|node_memory_SReclaimable_bytes|node_memory_SUnreclaim_bytes|node_memory_ShmemHugePages_bytes|node_memory_ShmemPmdMapped_bytes|node_memory_Shmem_bytes|node_memory_Slab_bytes|node_memory_SwapTotal_bytes|node_memory_VmallocChunk_bytes|node_memory_VmallocTotal_bytes|node_memory_VmallocUsed_bytes|node_memory_WritebackTmp_bytes|node_memory_Writeback_bytes|node_netstat_Icmp6_InErrors|node_netstat_Icmp6_InMsgs|node_netstat_Icmp6_OutMsgs|node_netstat_Icmp_InErrors|node_netstat_Icmp_InMsgs|node_netstat_Icmp_OutMsgs|node_netstat_IpExt_InOctets|node_netstat_IpExt_OutOctets|node_netstat_TcpExt_ListenDrops|node_netstat_TcpExt_ListenOverflows|node_netstat_TcpExt_TCPSynRetrans|node_netstat_Tcp_InErrs|node_netstat_Tcp_InSegs|node_netstat_Tcp_OutRsts|node_netstat_Tcp_OutSegs|node_netstat_Tcp_RetransSegs|node_netstat_Udp6_InDatagrams|node_netstat_Udp6_InErrors|node_netstat_Udp6_NoPorts|node_netstat_Udp6_OutDatagrams|node_netstat_Udp6_RcvbufErrors|node_netstat_Udp6_SndbufErrors|node_netstat_UdpLite_InErrors|node_netstat_Udp_InDatagrams|node_netstat_Udp_InErrors|node_netstat_Udp_NoPorts|node_netstat_Udp_OutDatagrams|node_netstat_Udp_RcvbufErrors|node_netstat_Udp_SndbufErrors|node_network_carrier|node_network_info|node_network_mtu_bytes|node_network_receive_bytes_total|node_network_receive_compressed_total|node_network_receive_drop_total|node_network_receive_errs_total|node_network_receive_fifo_total|node_network_receive_multicast_total|node_network_receive_packets_total|node_network_speed_bytes|node_network_transmit_bytes_total|node_network_transmit_compressed_total|node_network_transmit_drop_total|node_network_transmit_errs_total|node_network_transmit_fifo_total|node_network_transmit_multicast_total|node_network_transmit_packets_total|node_network_transmit_queue_length|node_network_up|node_nf_conntrack_entries|node_nf_conntrack_entries_limit|node_os_info|node_sockstat_FRAG6_inuse|node_sockstat_FRAG_inuse|node_sockstat_RAW6_inuse|node_sockstat_RAW_inuse|node_sockstat_TCP6_inuse|node_sockstat_TCP_alloc|node_sockstat_TCP_inuse|node_sockstat_TCP_mem|node_sockstat_TCP_mem_bytes|node_sockstat_TCP_orphan|node_sockstat_TCP_tw|node_sockstat_UDP6_inuse|node_sockstat_UDPLITE6_inuse|node_sockstat_UDPLITE_inuse|node_sockstat_UDP_inuse|node_sockstat_UDP_mem|node_sockstat_UDP_mem_bytes|node_sockstat_sockets_used|node_softnet_dropped_total|node_softnet_processed_total|node_softnet_times_squeezed_total|node_systemd_unit_state|node_textfile_scrape_error|node_time_zone_offset_seconds|node_timex_estimated_error_seconds|node_timex_maxerror_seconds|node_timex_offset_seconds|node_timex_sync_status|node_uname_info|node_vmstat_oom_kill|node_vmstat_pgfault|node_vmstat_pgmajfault|node_vmstat_pgpgin|node_vmstat_pgpgout|node_vmstat_pswpin|node_vmstat_pswpout|process_max_fds|process_open_fds\"
    action        = \"keep\"
  }
}

loki.source.journal \"logs_integrations_integrations_node_exporter_journal_scrape\" {
  max_age       = \"24h0m0s\"
  relabel_rules = discovery.relabel.logs_integrations_integrations_node_exporter_journal_scrape.rules
  forward_to    = [loki.write.grafana_loki.receiver]
}

local.file_match \"logs_integrations_integrations_node_exporter_direct_scrape\" {
  path_targets = [{
    __address__ = \"localhost\",
    __path__    = \"/var/log/{syslog,messages,*.log}\",
    instance    = \"\${HOSTNAME}\",
    job         = \"integrations/node_exporter\",
  }]
}

discovery.relabel \"logs_integrations_integrations_node_exporter_journal_scrape\" {
  targets = []

  rule {
    source_labels = [\"__journal__systemd_unit\"]
    target_label  = \"unit\"
  }

  rule {
    source_labels = [\"__journal__boot_id\"]
    target_label  = \"boot_id\"
  }

  rule {
    source_labels = [\"__journal__transport\"]
    target_label  = \"transport\"
  }

  rule {
    source_labels = [\"__journal_priority_keyword\"]
    target_label  = \"level\"
  }

   rule {
    source_labels = [\"__journal__hostname\"]
    target_label  = \"hostname\"
  }
}

loki.source.file \"logs_integrations_integrations_node_exporter_direct_scrape\" {
  targets    = local.file_match.logs_integrations_integrations_node_exporter_direct_scrape.targets
  forward_to = [loki.write.grafana_loki.receiver]
}

prometheus.remote_write \"mimir\" {
	endpoint {
		url = json_path(local.file.endpoints.content, \".metrics.url\")[0]
	}
}

loki.write \"grafana_loki\" {
  endpoint {
    url = json_path(local.file.endpoints.content, \".logs.url\")[0]
  }
}
EOF"

    echo "Creating Grafana Alloy systemd service..."
    sudo bash -c "cat << EOF > /etc/systemd/system/alloy.service
[Unit]
Description=Grafana Alloy - Vendor-agnostic OpenTelemetry Collector
Documentation=https://grafana.com/docs/alloy
Wants=network-online.target
After=network-online.target

[Service]
Restart=always
User=alloy
Environment=HOSTNAME=${HOSTNAME}
Environment=ALLOY_DEPLOY_MODE=deb
WorkingDirectory=/var/lib/alloy
ExecStart=/usr/local/bin/alloy run --server.http.listen-addr=0.0.0.0:12345 --storage.path=/var/lib/alloy/data --stability.level=public-preview /etc/alloy/config.alloy
ExecReload=/usr/bin/env kill -HUP \$MAINPID
TimeoutStopSec=20s
SendSIGKILL=no

[Install]
WantedBy=multi-user.target
EOF"

    echo "Reloading systemd, enabling and starting Grafana Alloy service..."
    sudo systemctl daemon-reload
    sudo systemctl enable alloy
    sudo systemctl start alloy
    echo "Grafana Alloy has been installed and started successfully."

    rm -rf "$TEMP_DIR"
    echo "Temporary files removed."
}

function uninstall_alloy {
    echo "Stopping and disabling Grafana Alloy service..."
    sudo systemctl stop alloy || echo "Grafana Alloy service is not running."
    sudo systemctl disable alloy || echo "Grafana Alloy service is not enabled."

    echo "Removing Grafana Alloy service file and configurations..."
    sudo rm -f /etc/systemd/system/alloy.service
    sudo systemctl daemon-reload

    sudo rm -f /usr/local/bin/alloy
    sudo rm -rf /etc/alloy
    sudo rm -rf /var/lib/alloy

    echo "Removing alloy user..."
    sudo userdel alloy || echo "Alloy user does not exist."

    echo "Grafana Alloy has been removed successfully."
}

case "$1" in
    install)
        install_alloy
        ;;
    uninstall)
        uninstall_alloy
        ;;
    *)
        echo "Usage: $0 {install|uninstall}"
        exit 1
esac
