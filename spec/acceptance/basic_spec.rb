 require 'spec_helper_acceptance'

describe 'firewall type', :unless => UNSUPPORTED_PLATFORMS.include?(fact('osfamily')) do

  before(:all) do
    shell('rm -rf /etc/firewalld/zones/test_zone.xml; service firewalld restart || true')
  end

  describe 'firewalld basic tests' do
    context 'create 1 zone 2 rich rules 2 services 2 ports' do
      it 'applies' do
        pp = <<-EOS
          class {'firewalld':}

          firewalld_zone { 'test_zone':
            ensure           => present,
            target           => '%%REJECT%%',
            purge_rich_rules => true,
            purge_services   => true,
            purge_ports      => true,
            interfaces       => ['lo'],
          }

          firewalld_rich_rule { 'Rich Rule 1':
            ensure => present,
            zone   => 'test_zone',
            source => '192.168.1.2/32',
            service => 'ssh',
            action  => 'accept',
          }

          firewalld_rich_rule { 'Rich Rule 2':
            ensure => present,
            zone   => 'test_zone',
            source => '192.168.2.2/32',
            service => 'ntp',
            action  => 'accept',
          }

          firewalld_service { 'Allow HTTP':
            ensure  => 'present',
            service => 'http',
            zone    => 'test_zone',
          }

          firewalld_service { 'Allow HTTPS':
            ensure  => 'present',
            service => 'https',
            zone    => 'test_zone',
          }

          firewalld_port { 'Open port 4337':
            ensure   => present,
            zone     => 'test_zone',
            port     => 4337,
            protocol => 'tcp',
          }

          firewalld_port { 'Open port 4338':
            ensure   => present,
            zone     => 'test_zone',
            port     => 4338,
            protocol => 'udp',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)
      end

      it 'should contain the rule' do
         shell('firewall-cmd --zone=test_zone --list-all') do |r|
           expect(r.stdout).to match(/test_zone \(active\)/)
           expect(r.stdout).to match(/interfaces: lo/)
           expect(r.stdout).to match(/services: http https/)
           expect(r.stdout).to match(/ports: 4338\/udp 4337\/tcp/)
           expect(r.stdout).to match(/rule family=\"ipv4\" source address=\"192.168.1.2\/32\" service name=\"ssh\" accept/)
           expect(r.stdout).to match(/rule family=\"ipv4\" source address=\"192.168.2.2\/32\" service name=\"ntp\" accept/)
         end
      end

      it 'cleanup' do
        shell('rm -rf /etc/firewalld/zones/test_zone.xml; service firewalld restart || true')
      end
    end

    context 'update zone test' do
      it 'applies' do
        pp = <<-EOS
          class {'firewalld':}

          firewalld_zone { 'test_zone2':
            ensure           => present,
            target           => '%%REJECT%%',
            purge_rich_rules => true,
            purge_services   => true,
            purge_ports      => true,
            interfaces       => ['lo'],
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)

        pp = <<-EOS
          class {'firewalld':}

          firewalld_zone { 'test_zone2':
            ensure           => present,
            target           => 'ACCEPT',
            purge_rich_rules => true,
            purge_services   => true,
            purge_ports      => true,
            interfaces       => ['lo'],
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)
      end

      it 'cleanup' do
        shell('rm -rf /etc/firewalld/zones/test_zone2.xml; service firewalld restart || true')
      end
    end

    context 'delete zone test' do
      it 'applies' do
        pp = <<-EOS
          class {'firewalld':}

          firewalld_zone { 'test_zone3':
            ensure           => present,
            target           => '%%REJECT%%',
            purge_rich_rules => true,
            purge_services   => true,
            purge_ports      => true,
            interfaces       => ['lo'],
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)

        pp = <<-EOS
          class {'firewalld':}

          firewalld_zone { 'test_zone3':
            ensure           => absent,
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)
      end

      it 'cleanup' do
        shell('rm -rf /etc/firewalld/zones/test_zone3.xml; service firewalld restart || true')
      end
    end

    context 'delete rich rule test' do
      it 'applies' do
        pp = <<-EOS
          class {'firewalld':}

          firewalld_zone { 'test_zone4':
            ensure           => present,
            target           => '%%REJECT%%',
            purge_rich_rules => true,
            purge_services   => true,
            purge_ports      => true,
            interfaces       => ['lo'],
          }

          firewalld_rich_rule { 'Rich Rule 1':
            ensure => present,
            zone   => 'test_zone4',
            source => '192.168.1.2/32',
            service => 'ssh',
            action  => 'accept',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)

        pp = <<-EOS
          class {'firewalld':}

          firewalld_zone { 'test_zone4':
            ensure           => present,
            target           => '%%REJECT%%',
            purge_rich_rules => true,
            purge_services   => true,
            purge_ports      => true,
            interfaces       => ['lo'],
          }

          firewalld_rich_rule { 'Rich Rule 1':
            ensure => absent,
            zone   => 'test_zone4',
            source => '192.168.1.2/32',
            service => 'ssh',
            action  => 'accept',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)
      end

      it 'cleanup' do
        shell('rm -rf /etc/firewalld/zones/test_zone4.xml; service firewalld restart || true')
      end
    end

    context 'delete service test' do
      it 'applies' do
        pp = <<-EOS
          class {'firewalld':}

          firewalld_zone { 'test_zone5':
            ensure           => present,
            target           => '%%REJECT%%',
            purge_rich_rules => true,
            purge_services   => true,
            purge_ports      => true,
            interfaces       => ['lo'],
          }

          firewalld_service { 'Allow HTTPS':
            ensure  => 'present',
            service => 'https',
            zone    => 'test_zone5',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)

        pp = <<-EOS
          class {'firewalld':}

          firewalld_zone { 'test_zone5':
            ensure           => present,
            target           => '%%REJECT%%',
            purge_rich_rules => true,
            purge_services   => true,
            purge_ports      => true,
            interfaces       => ['lo'],
          }

          firewalld_service { 'Allow HTTPS':
            ensure  => 'absent',
            service => 'https',
            zone    => 'test_zone5',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)
      end

      it 'cleanup' do
        shell('rm -rf /etc/firewalld/zones/test_zone5.xml; service firewalld restart || true')
      end
    end

    context 'delete port test' do
      it 'applies' do
        pp = <<-EOS
          class {'firewalld':}

          firewalld_zone { 'test_zone6':
            ensure           => present,
            target           => '%%REJECT%%',
            purge_rich_rules => true,
            purge_services   => true,
            purge_ports      => true,
            interfaces       => ['lo'],
          }

          firewalld_port { 'Open port 4337':
            ensure   => present,
            zone     => 'test_zone6',
            port     => 4337,
            protocol => 'tcp',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)

        pp = <<-EOS
          class {'firewalld':}

          firewalld_zone { 'test_zone6':
            ensure           => present,
            target           => '%%REJECT%%',
            purge_rich_rules => true,
            purge_services   => true,
            purge_ports      => true,
            interfaces       => ['lo'],
          }

          firewalld_port { 'Open port 4337':
            ensure   => absent,
            zone     => 'test_zone6',
            port     => 4337,
            protocol => 'tcp',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)
      end

      it 'cleanup' do
        shell('rm -rf /etc/firewalld/zones/test_zone6.xml; service firewalld restart || true')
      end
    end
  end
end
