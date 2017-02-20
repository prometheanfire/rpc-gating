def prepare() {
  dir("openstack-ansible-ops") {
    git url: env.OSA_OPS_REPO, branch: env.OSA_OPS_BRANCH
  }
  dir("openstack-ansible-ops/multi-node-aio") {
    common.conditionalStage(
      stage_name: 'Prepare Multi-Node AIO',
      stage: {
        common.run_script(
          script: 'build.sh',
          environment_vars: [
            "PARTITION_HOST=${env.PARTITION_HOST}",
            "NETWORK_BASE=172.29",
            "DEFAULT_IMAGE=${env.DEFAULT_IMAGE}",
            "OSA_BRANCH=${env.OPENSTACK_ANSIBLE_BRANCH}",
            "RUN_OSA=false"]
        )
      } //stage
    ) //conditionalStage
  } //dir
  common.conditionalStage(
    stage_name: 'Prepare RPC Configs',
    stage: {
      dir("/opt/rpc-openstack") {
        git branch: env.RPC_BRANCH, url: env.RPC_REPO
        sh """
        git submodule update --init

        sudo cp /etc/openstack_deploy/user_variables.yml /etc/openstack_deploy/user_variables.yml.bak
        sudo cp -R /opt/rpc-openstack/openstack-ansible/etc/openstack_deploy /etc
        sudo cp /etc/openstack_deploy/user_variables.yml.bak /etc/openstack_deploy/user_variables.yml

        sudo mv /etc/openstack_deploy/user_secrets.yml /etc/openstack_deploy/user_osa_secrets.yml
        sudo cp /opt/rpc-openstack/rpcd/etc/openstack_deploy/user_*_defaults.yml /etc/openstack_deploy
        sudo cp /opt/rpc-openstack/rpcd/etc/openstack_deploy/user_rpco_secrets.yml /etc/openstack_deploy
        sudo cp /opt/rpc-openstack/rpcd/etc/openstack_deploy/env.d/* /etc/openstack_deploy/env.d

        sudo -E sh -c 'echo "
        apply_security_hardening: false" >> /etc/openstack_deploy/user_osa_variables_overrides.yml'
        """
      } //dir
    } //stage
  ) //conditionalStage
}
return this;