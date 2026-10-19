"""
OpenSearch Index Naming and ILM Policy Management.
Provides monthly rollover index naming and Index Lifecycle Management policies.
"""

import os
from datetime import UTC, datetime
from typing import Any

# Default index prefix from environment
OPENSEARCH_INDEX_PREFIX = os.getenv("OPENSEARCH_INDEX_PREFIX", "security-events")


def get_security_events_index_name(date: datetime | None = None) -> str:
    """
    Generate the OpenSearch index name for security events with monthly rollover.
    
    Format: {prefix}-YYYY.MM
    Example: security-events-2026.10
    
    Args:
        date: The date to generate the index name for. Defaults to current UTC time.
        
    Returns:
        The index name string.
    """
    if date is None:
        date = datetime.now(UTC)
    
    # Ensure UTC timezone
    if date.tzinfo is None:
        date = date.replace(tzinfo=UTC)
    else:
        date = date.astimezone(UTC)
    
    return f"{OPENSEARCH_INDEX_PREFIX}-{date.strftime('%Y.%m')}"


def get_threat_intel_index_name(date: datetime | None = None) -> str:
    """
    Generate the OpenSearch index name for threat intelligence with monthly rollover.
    
    Format: threat-intel-indicators-YYYY.MM
    Example: threat-intel-indicators-2026.10
    """
    if date is None:
        date = datetime.now(UTC)
    
    if date.tzinfo is None:
        date = date.replace(tzinfo=UTC)
    else:
        date = date.astimezone(UTC)
    
    return f"threat-intel-indicators-{date.strftime('%Y.%m')}"


def get_security_events_alias() -> str:
    """
    Get the alias name for the current security events index.
    Used for searching across current and recent indices.
    """
    return f"{OPENSEARCH_INDEX_PREFIX}-current"


def get_ilm_policy_name() -> str:
    """Get the ILM policy name for security events indices."""
    return f"{OPENSEARCH_INDEX_PREFIX}-ilm-policy"


# ILM Policy definition for security events indices
SECURITY_EVENTS_ILM_POLICY: dict[str, Any] = {
    "policy": {
        "description": "ILM policy for security events indices with monthly rollover",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [
                    {
                        "rollover": {
                            "min_size": "10gb",
                            "min_index_age": "7d",
                            "max_docs": 50000000,
                        }
                    }
                ],
                "transitions": [
                    {
                        "state_name": "warm",
                        "conditions": {
                            "min_index_age": "7d",
                        },
                    }
                ],
            },
            {
                "name": "warm",
                "actions": [
                    {
                        "forcemerge": {
                            "max_num_segments": 1,
                        }
                    },
                    {
                        "shrink": {
                            "number_of_shards": 1,
                        }
                    },
                ],
                "transitions": [
                    {
                        "state_name": "cold",
                        "conditions": {
                            "min_index_age": "30d",
                        },
                    }
                ],
            },
            {
                "name": "cold",
                "actions": [
                    {
                        "readonly": {}
                    }
                ],
                "transitions": [
                    {
                        "state_name": "delete",
                        "conditions": {
                            "min_index_age": "365d",
                        },
                    }
                ],
            },
            {
                "name": "delete",
                "actions": [
                    {
                        "delete": {}
                    }
                ],
            },
        ],
        "ism_template": [
            {
                "index_patterns": [f"{OPENSEARCH_INDEX_PREFIX}-*"],
                "priority": 100,
            }
        ],
    }
}


# ILM Policy for threat intel indices
THREAT_INTEL_ILM_POLICY: dict[str, Any] = {
    "policy": {
        "description": "ILM policy for threat intelligence indices with monthly rollover",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [
                    {
                        "rollover": {
                            "min_size": "5gb",
                            "min_index_age": "7d",
                            "max_docs": 10000000,
                        }
                    }
                ],
                "transitions": [
                    {
                        "state_name": "warm",
                        "conditions": {
                            "min_index_age": "30d",
                        },
                    }
                ],
            },
            {
                "name": "warm",
                "actions": [
                    {
                        "forcemerge": {
                            "max_num_segments": 1,
                        }
                    },
                ],
                "transitions": [
                    {
                        "state_name": "cold",
                        "conditions": {
                            "min_index_age": "90d",
                        },
                    }
                ],
            },
            {
                "name": "cold",
                "actions": [
                    {
                        "readonly": {}
                    }
                ],
                "transitions": [
                    {
                        "state_name": "delete",
                        "conditions": {
                            "min_index_age": "730d",  # 2 years retention for threat intel
                        },
                    }
                ],
            },
            {
                "name": "delete",
                "actions": [
                    {
                        "delete": {}
                    }
                ],
            },
        ],
        "ism_template": [
            {
                "index_patterns": ["threat-intel-indicators-*"],
                "priority": 100,
            }
        ],
    }
}


async def setup_ilm_policies(opensearch_client) -> bool:
    """
    Set up ILM policies in OpenSearch.
    
    Args:
        opensearch_client: AsyncOpenSearch client instance.
        
    Returns:
        True if successful, False otherwise.
    """
    from opensearchpy.exceptions import OpenSearchException
    
    try:
        # Check if policies already exist
        for policy_name in [get_ilm_policy_name(), "threat-intel-indicators-ilm-policy"]:
            try:
                await opensearch_client.transport.perform_request(
                    "GET", f"/_plugins/_ism/policies/{policy_name}"
                )
            except OpenSearchException:
                # Policy doesn't exist, create it
                if policy_name == get_ilm_policy_name():
                    await opensearch_client.transport.perform_request(
                        "PUT",
                        f"/_plugins/_ism/policies/{policy_name}",
                        body=SECURITY_EVENTS_ILM_POLICY,
                    )
                else:
                    await opensearch_client.transport.perform_request(
                        "PUT",
                        f"/_plugins/_ism/policies/{policy_name}",
                        body=THREAT_INTEL_ILM_POLICY,
                    )
                print(f"Created ILM policy: {policy_name}")
        
        return True
    except Exception as e:
        print(f"Failed to set up ILM policies: {e}")
        return False


async def create_initial_indices(opensearch_client) -> bool:
    """
    Create initial indices with proper settings and aliases.
    
    Args:
        opensearch_client: AsyncOpenSearch client instance.
        
    Returns:
        True if successful, False otherwise.
    """
    
    try:
        current_index = get_security_events_index_name()
        alias = get_security_events_alias()
        
        # Check if index already exists
        exists = await opensearch_client.indices.exists(index=current_index)
        if not exists:
            # Create index with settings
            index_settings = {
                "settings": {
                    "number_of_shards": 3,
                    "number_of_replicas": 1,
                    "refresh_interval": "5s",
                    "index.sort.field": "@timestamp",
                    "index.sort.order": "desc",
                },
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event_id": {"type": "keyword"},
                        "correlation_id": {"type": "keyword"},
                        "source_ip": {"type": "ip"},
                        "destination_ip": {"type": "ip"},
                        "rule_id": {"type": "keyword"},
                        "rule_name": {"type": "keyword"},
                        "technique_id": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "rating": {"type": "keyword"},
                        "risk_score": {"type": "float"},
                        "hostname": {"type": "keyword"},
                        "username": {"type": "keyword"},
                        "raw_payload": {"type": "object", "enabled": False},
                    }
                },
            }
            
            await opensearch_client.indices.create(
                index=current_index,
                body=index_settings,
            )
            
            # Add alias
            await opensearch_client.indices.put_alias(
                index=current_index,
                name=alias,
            )
            
            print(f"Created initial index: {current_index} with alias: {alias}")
        
        return True
    except Exception as e:
        print(f"Failed to create initial indices: {e}")
        return False