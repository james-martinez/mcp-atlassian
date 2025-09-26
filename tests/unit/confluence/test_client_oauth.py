"""Tests for the ConfluenceClient with OAuth authentication."""

import os
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from mcp_atlassian.confluence.client import ConfluenceClient
from mcp_atlassian.confluence.config import ConfluenceConfig
from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.utils.oauth import BYOAccessTokenOAuthConfig, OAuthConfig


class TestConfluenceClientOAuth:
    """Tests for ConfluenceClient with OAuth authentication."""

    def test_init_with_oauth_config(self):
        """Test initializing the client with OAuth configuration."""
        oauth_config = OAuthConfig(
            client_id="test-client-id",
            client_secret="test-client-secret",
            redirect_uri="https://example.com/callback",
            scope="read:confluence-space.summary write:confluence-space",
            cloud_id="test-cloud-id",
            access_token="test-access-token",
            refresh_token="test-refresh-token",
            expires_at=9999999999.0,
        )

        config = ConfluenceConfig(
            url="https://test.atlassian.net/wiki",
            auth_type="oauth",
            oauth_config=oauth_config,
        )

        with (
            patch("mcp_atlassian.confluence.client.Confluence") as mock_confluence,
            patch(
                "mcp_atlassian.confluence.client.configure_oauth_session"
            ) as mock_configure_oauth,
            patch(
                "mcp_atlassian.confluence.client.configure_ssl_verification"
            ) as mock_configure_ssl,
            patch.object(
                OAuthConfig,
                "is_token_expired",
                new_callable=PropertyMock,
                return_value=False,
            ),
            patch.object(oauth_config, "ensure_valid_token", return_value=True),
            patch(
                "mcp_atlassian.preprocessing.confluence.ConfluencePreprocessor"
            ) as mock_preprocessor,
        ):
            mock_configure_oauth.return_value = True
            client = ConfluenceClient(config=config)

            mock_configure_oauth.assert_called_once()
            mock_confluence.assert_called_once()
            confluence_kwargs = mock_confluence.call_args[1]
            assert (
                confluence_kwargs["url"]
                == f"https://api.atlassian.com/ex/confluence/{oauth_config.cloud_id}"
            )
            assert "session" in confluence_kwargs
            assert confluence_kwargs["cloud"] is True
            mock_configure_ssl.assert_called_once()

    def test_init_with_oauth_missing_cloud_id(self):
        """Test initializing the client with OAuth but missing cloud_id."""
        oauth_config = OAuthConfig(
            client_id="test-client-id",
            client_secret="test-client-secret",
            redirect_uri="https://example.com/callback",
            scope="read:confluence-space.summary",
            access_token="test-access-token",
        )
        config = ConfluenceConfig(
            url="https://test.atlassian.net/wiki",
            auth_type="oauth",
            oauth_config=oauth_config,
        )
        with pytest.raises(
            ValueError, match="OAuth authentication requires a valid cloud_id"
        ):
            ConfluenceClient(config=config)

    def test_init_with_oauth_failed_session_config(self):
        """Test initializing with OAuth but failed session configuration."""
        oauth_config = OAuthConfig(
            client_id="test-client-id",
            client_secret="test-client-secret",
            redirect_uri="https://example.com/callback",
            scope="read:confluence-space.summary",
            cloud_id="test-cloud-id",
            access_token="test-access-token",
        )
        config = ConfluenceConfig(
            url="https://test.atlassian.net/wiki",
            auth_type="oauth",
            oauth_config=oauth_config,
        )
        with (
            patch("mcp_atlassian.confluence.client.Confluence"),
            patch(
                "mcp_atlassian.confluence.client.configure_oauth_session"
            ) as mock_configure_oauth,
            patch("mcp_atlassian.confluence.client.configure_ssl_verification"),
            patch("mcp_atlassian.preprocessing.confluence.ConfluencePreprocessor"),
        ):
            mock_configure_oauth.return_value = False
            with pytest.raises(
                MCPAtlassianAuthenticationError,
                match="Failed to configure OAuth session",
            ):
                ConfluenceClient(config=config)

    def test_init_with_byo_access_token_oauth_config(self):
        """Test initializing with BYO Access Token OAuth configuration."""
        byo_oauth_config = BYOAccessTokenOAuthConfig(
            cloud_id="test-cloud-id", access_token="my-byo-token"
        )
        config = ConfluenceConfig(
            url="https://test.atlassian.net/wiki",
            auth_type="oauth",
            oauth_config=byo_oauth_config,
        )
        with (
            patch("mcp_atlassian.confluence.client.Confluence") as mock_confluence,
            patch(
                "mcp_atlassian.confluence.client.configure_oauth_session"
            ) as mock_configure_oauth,
            patch("mcp_atlassian.confluence.client.configure_ssl_verification"),
            patch("mcp_atlassian.preprocessing.confluence.ConfluencePreprocessor"),
        ):
            mock_configure_oauth.return_value = True
            client = ConfluenceClient(config=config)
            mock_configure_oauth.assert_called_once()
            mock_confluence.assert_called_once()
            confluence_kwargs = mock_confluence.call_args[1]
            assert (
                confluence_kwargs["url"]
                == f"https://api.atlassian.com/ex/confluence/{byo_oauth_config.cloud_id}"
            )

    def test_init_with_byo_oauth_missing_cloud_id(self):
        """Test initializing with BYO OAuth but missing cloud_id."""
        byo_oauth_config = BYOAccessTokenOAuthConfig(
            cloud_id="", access_token="my-byo-token"
        )
        config = ConfluenceConfig(
            url="https://test.atlassian.net/wiki",
            auth_type="oauth",
            oauth_config=byo_oauth_config,
        )
        with pytest.raises(
            ValueError, match="OAuth authentication requires a valid cloud_id"
        ):
            ConfluenceClient(config=config)

    def test_init_with_byo_oauth_failed_session_config(self):
        """Test init with BYO OAuth but failed session configuration."""
        byo_oauth_config = BYOAccessTokenOAuthConfig(
            cloud_id="test-cloud-id", access_token="my_byo_token"
        )
        config = ConfluenceConfig(
            url="https://test.atlassian.net/wiki",
            auth_type="oauth",
            oauth_config=byo_oauth_config,
        )
        with (
            patch("mcp_atlassian.confluence.client.Confluence"),
            patch(
                "mcp_atlassian.confluence.client.configure_oauth_session"
            ) as mock_configure_oauth,
            patch("mcp_atlassian.confluence.client.configure_ssl_verification"),
            patch("mcp_atlassian.preprocessing.confluence.ConfluencePreprocessor"),
        ):
            mock_configure_oauth.return_value = False
            with pytest.raises(
                MCPAtlassianAuthenticationError,
                match="Failed to configure OAuth session",
            ):
                ConfluenceClient(config=config)

    def test_init_with_byo_oauth_empty_token_failed_session_config(self):
        """Test init with BYO OAuth, empty token, so session config fails."""
        byo_oauth_config_empty_token = BYOAccessTokenOAuthConfig(
            cloud_id="test-cloud-id", access_token=""
        )
        config = ConfluenceConfig(
            url="https://test.atlassian.net/wiki",
            auth_type="oauth",
            oauth_config=byo_oauth_config_empty_token,
        )
        with (
            patch("mcp_atlassian.confluence.client.Confluence"),
            patch("mcp_atlassian.confluence.client.configure_ssl_verification"),
            patch("mcp_atlassian.preprocessing.confluence.ConfluencePreprocessor"),
        ):
            with pytest.raises(
                MCPAtlassianAuthenticationError,
                match="Failed to configure OAuth session",
            ):
                ConfluenceClient(config=config)

    def test_from_env_with_oauth(self):
        """Test client creation from env with full OAuth config."""
        env_vars = {
            "CONFLUENCE_URL": "https://test.atlassian.net/wiki",
            "ATLASSIAN_OAUTH_CLIENT_ID": "env-client-id",
            "ATLASSIAN_OAUTH_CLIENT_SECRET": "env-client-secret",
            "ATLASSIAN_OAUTH_REDIRECT_URI": "https://example.com/callback",
            "ATLASSIAN_OAUTH_SCOPE": "read:confluence-space.summary",
            "ATLASSIAN_OAUTH_CLOUD_ID": "env-cloud-id",
        }
        mock_oauth_config = MagicMock()
        mock_oauth_config.cloud_id = "env-cloud-id"
        mock_oauth_config.access_token = "env-access-token"
        with (
            patch.dict(os.environ, env_vars),
            patch(
                "mcp_atlassian.confluence.config.get_oauth_config_from_env",
                return_value=mock_oauth_config,
            ),
            patch.object(
                OAuthConfig,
                "is_token_expired",
                new_callable=PropertyMock,
                return_value=False,
            ),
            patch.object(mock_oauth_config, "ensure_valid_token", return_value=True),
            patch("mcp_atlassian.confluence.client.Confluence") as mock_confluence,
            patch(
                "mcp_atlassian.confluence.client.configure_oauth_session",
                return_value=True,
            ),
            patch("mcp_atlassian.confluence.client.configure_ssl_verification"),
            patch("mcp_atlassian.preprocessing.confluence.ConfluencePreprocessor"),
        ):
            client = ConfluenceClient()
            assert client.config.auth_type == "oauth"
            mock_confluence.assert_called_once()
            confluence_kwargs = mock_confluence.call_args[1]
            assert (
                confluence_kwargs["url"]
                == f"https://api.atlassian.com/ex/confluence/{mock_oauth_config.cloud_id}"
            )

    def test_from_env_with_byo_token_oauth(self):
        """Test client creation from env with BYO token OAuth config."""
        env_vars = {
            "CONFLUENCE_URL": "https://test.atlassian.net/wiki",
            "ATLASSIAN_OAUTH_ACCESS_TOKEN": "env-byo-access-token",
            "ATLASSIAN_OAUTH_CLOUD_ID": "env-byo-cloud-id",
        }
        mock_byo_oauth_config = MagicMock(spec=BYOAccessTokenOAuthConfig)
        mock_byo_oauth_config.cloud_id = "env-byo-cloud-id"
        mock_byo_oauth_config.access_token = "env-byo-access-token"
        with (
            patch.dict(os.environ, env_vars),
            patch(
                "mcp_atlassian.confluence.config.get_oauth_config_from_env",
                return_value=mock_byo_oauth_config,
            ),
            patch("mcp_atlassian.confluence.client.Confluence") as mock_confluence,
            patch(
                "mcp_atlassian.confluence.client.configure_oauth_session",
                return_value=True,
            ),
            patch("mcp_atlassian.confluence.client.configure_ssl_verification"),
            patch("mcp_atlassian.preprocessing.confluence.ConfluencePreprocessor"),
        ):
            client = ConfluenceClient()
            assert client.config.auth_type == "oauth"
            mock_confluence.assert_called_once()
            confluence_kwargs = mock_confluence.call_args[1]
            assert (
                confluence_kwargs["url"]
                == f"https://api.atlassian.com/ex/confluence/{mock_byo_oauth_config.cloud_id}"
            )

    def test_from_env_with_no_oauth_config_found(self):
        """Test client creation from env when no OAuth config is found by the utility."""
        env_vars = {
            "CONFLUENCE_URL": "https://test.atlassian.net/wiki",
            # Deliberately missing other auth variables (basic, token, or complete OAuth)
        }

        with (
            patch.dict(os.environ, env_vars, clear=True),
            patch(
                "mcp_atlassian.confluence.config.get_oauth_config_from_env",
                return_value=None,  # Simulate no OAuth config found by the utility
            ),
        ):
            # ConfluenceConfig.from_env should raise ValueError if no auth can be determined
            with pytest.raises(
                ValueError,
                match="Cloud authentication requires CONFLUENCE_USERNAME/CONFLUENCE_API_TOKEN, OAuth, or a Cookie header in CONFLUENCE_CUSTOM_HEADERS",
            ):
                ConfluenceClient()  # This will call ConfluenceConfig.from_env()
