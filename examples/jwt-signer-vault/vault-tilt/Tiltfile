load('ext://helm_remote', 'helm_remote')

helm_remote(
  'vault',
  repo_name='hashicorp',
  repo_url='https://helm.releases.hashicorp.com',
  values='vault-values.yml'
)
k8s_resource(
  workload='vault',
  port_forwards=8200
)

k8s_yaml('vault-init.yml')
k8s_resource(
  workload='vault-init',
  resource_deps=['vault']
)

update_env={'VAULT_ADDR': 'http://localhost:8200', 'VAULT_TOKEN': 'root'}
