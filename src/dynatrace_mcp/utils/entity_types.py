"""Dynatrace entity types."""

from __future__ import annotations

_PREFIX_TO_TYPE_BASICS: dict[str, str] = {
    # Core applications and services
    "APPLICATION": "dt.entity.application",
    "SERVICE": "dt.entity.service",
    "MOBILE_APPLICATION": "dt.entity.mobile_application",
    "CUSTOM_APPLICATION": "dt.entity.custom_application",
    # Infrastructure
    "HOST": "dt.entity.host",
    "HOST_GROUP": "dt.entity.host_group",
    "PROCESS_GROUP": "dt.entity.process_group",
    "DISK": "dt.entity.disk",
    "NETWORK_INTERFACE": "dt.entity.network_interface",
    # Cloud
    "CLOUD_APPLICATION": "dt.entity.cloud_application",
    "CLOUD_APPLICATION_NAMESPACE": "dt.entity.cloud_application_namespace",
    # Containers
    "CONTAINER_GROUP": "dt.entity.container_group",
    # Environment / OS
    "ENVIRONMENT": "dt.entity.environment",
    "OS": "dt.entity.os",
    # Synthetic
    "SYNTHETIC_TEST": "dt.entity.synthetic_test",
    "SYNTHETIC_LOCATION": "dt.entity.synthetic_location",
    # Custom devices
    "CUSTOM_DEVICE": "dt.entity.custom_device",
    "CUSTOM_DEVICE_GROUP": "dt.entity.custom_device_group",
    # Geolocation
    "GEOLOCATION": "dt.entity.geolocation",
    # Databases
    "RELATIONAL_DATABASE_SERVICE": "dt.entity.relational_database_service",
    # Kubernetes
    "KUBERNETES_NODE": "dt.entity.kubernetes_node",
    "KUBERNETES_CLUSTER": "dt.entity.kubernetes_cluster",
    "KUBERNETES_SERVICE": "dt.entity.kubernetes_service",
}

_PREFIX_TO_TYPE_ALL: dict[str, str] = {
    **_PREFIX_TO_TYPE_BASICS,
    "SERVICE_INSTANCE": "dt.entity.service_instance",
    "PROCESS_GROUP_INSTANCE": "dt.entity.process_group_instance",
    "CLOUD_APPLICATION_INSTANCE": "dt.entity.cloud_application_instance",
    "DCG_INSTANCE": "dt.entity.docker_container_group_instance",
    "CONTAINER_GROUP_INSTANCE": "dt.entity.container_group_instance",
    # AWS
    "EC2_INSTANCE": "dt.entity.ec2_instance",
    "AWS_LAMBDA_FUNCTION": "dt.entity.aws_lambda_function",
    "AWS_AVAILABILITY_ZONE": "dt.entity.aws_availability_zone",
    "AWS_APPLICATION_LOAD_BALANCER": "dt.entity.aws_application_load_balancer",
    "AWS_NETWORK_LOAD_BALANCER": "dt.entity.aws_network_load_balancer",
    # GCP
    "GCP_ZONE": "dt.entity.gcp_zone",
    # VMs
    "AZURE_VM": "dt.entity.azure_vm",
    "OPENSTACK_VM": "dt.entity.openstack_vm",
}

DYNATRACE_ENTITY_TYPES_BASICS: list[str] = sorted(_PREFIX_TO_TYPE_BASICS.values())
DYNATRACE_ENTITY_TYPES_ALL: list[str] = sorted(_PREFIX_TO_TYPE_ALL.values())


def get_entity_type_from_id(entity_id: str | None) -> str | None:
    """'PROCESS_GROUP-F84E4759809ADA84' -> 'dt.entity.process_group' (None if unknown)."""
    if not entity_id or not isinstance(entity_id, str) or "-" not in entity_id:
        return None
    prefix = entity_id.split("-", 1)[0]
    return _PREFIX_TO_TYPE_ALL.get(prefix)
