"""Shared fixtures for cred_proxy tests.

The credential store is now a pure in-memory dict (no keyring dependency),
so no backend mocking is required here.  Individual test modules provide
their own ``CredStore`` fixtures as needed.
"""
