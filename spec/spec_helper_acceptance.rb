require 'beaker-rspec'
require 'beaker/puppet_install_helper'

def do_catch_changes
  if default['platform'] =~ /el-5/
    return false
  else
    return true
  end
end

run_puppet_install_helper

UNSUPPORTED_PLATFORMS = ['windows','Solaris','Darwin']

RSpec.configure do |c|
  # Project root
  proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))

  # Readable test descriptions
  c.formatter = :documentation

  # Configure all nodes in nodeset
  c.before :suite do
    # Install module and dependencies
    hosts.each do |host|
      copy_module_to(host, :source => proj_root, :module_name => 'firewalld')
      on host, puppet('module install puppetlabs-stdlib --version 4.2.0'), { :acceptable_exit_codes => [0,1] }
    end
  end
end
