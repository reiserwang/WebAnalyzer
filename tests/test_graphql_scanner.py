import pytest
from unittest.mock import Mock, patch
from modules.graphql_scanner import GraphQLScanner

@pytest.fixture
def scanner():
    return GraphQLScanner()

@patch('requests.post')
def test_check_tracing_vulnerable(mock_post, scanner):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {
        "extensions": {"tracing": {}}
    }
    result = scanner._check_tracing("http://example.com/graphql")
    assert result["status"] == "Vulnerable"
    assert "Tracing is ENABLED" in result["details"]

@patch('requests.post')
def test_check_tracing_safe(mock_post, scanner):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {"data": {}}
    result = scanner._check_tracing("http://example.com/graphql")
    assert result["status"] == "Safe"

@patch('requests.post')
def test_check_field_suggestions_vulnerable(mock_post, scanner):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {
        "errors": [{"message": "Cannot query field 'typess'. Did you mean 'types'?"}]
    }
    result = scanner._check_field_suggestions("http://example.com/graphql")
    assert result["status"] == "Vulnerable"
    assert "Field suggestions are ENABLED" in result["details"]

@patch('requests.post')
def test_check_batching_array_vulnerable(mock_post, scanner):
    mock_post.return_value.status_code = 200
    # Returns list of 2 results
    mock_post.return_value.json.return_value = [{"data": {}}, {"data": {}}]
    result = scanner._check_batching("http://example.com/graphql")
    assert result["array_batching"]["status"] == "Vulnerable"

@patch('requests.post')
def test_check_batching_alias_vulnerable(mock_post, scanner):
    mock_post.return_value.status_code = 200
    # Array batching safe check first calls post, then alias calls post
    # We need side_effect for multiple calls or careful mocking
    # 1st call: Array batching (returns dict, so safe)
    # 2nd call: Alias overloading (returns success)
    mock_post.side_effect = [
        Mock(status_code=200, json=lambda: {"data": {}}), # Array check (safe)
        Mock(status_code=200, json=lambda: {"data": {"a0": {}, "a1": {}}}) # Alias check (vuln)
    ]
    
    result = scanner._check_batching("http://example.com/graphql")
    assert result["array_batching"]["status"] == "Safe"
    assert result["alias_overloading"]["status"] == "Vulnerable"

@patch('requests.get')
@patch('requests.post')
def test_check_csrf_vulnerable(mock_post, mock_get, scanner):
    # GET Check
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"data": {}}
    
    # POST Check
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {"data": {}}
    
    result = scanner._check_csrf("http://example.com/graphql")
    assert result["get_method"]["status"] == "Vulnerable"
    assert result["post_urlencoded"]["status"] == "Vulnerable"
