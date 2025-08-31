import requests
import threading
import queue
import time
from datetime import datetime
import os
from urllib.parse import urljoin, urlparse

class DirectoryBuster:
    def __init__(self, max_threads=10, timeout=5):
        self.max_threads = max_threads
        self.timeout = timeout
        self.found_dirs = []
        self.found_files = []

    def bust_directories(self, target_url, wordlist_path=None, extensions=None):
        """
        Perform directory busting on a web server
        Args:
            target_url: Base URL to scan
            wordlist_path: Path to wordlist file
            extensions: File extensions to check
        Returns:
            dict: Busting results
        """
        if extensions is None:
            extensions = ['php', 'html', 'txt', 'bak', 'old', 'zip', 'tar.gz']

        if wordlist_path is None:
            # Use default wordlist
            wordlist_path = self._get_default_wordlist()

        results = {
            'target': target_url,
            'scan_time': datetime.now().isoformat(),
            'directories': [],
            'files': [],
            'errors': []
        }

        try:
            # Read wordlist
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]

            print(f"Loaded {len(words)} words from wordlist")

            # Create queues and threads
            url_queue = queue.Queue()
            result_queue = queue.Queue()

            # Add URLs to queue
            for word in words:
                # Check directory
                dir_url = urljoin(target_url, word + '/')
                url_queue.put(('dir', word, dir_url))

                # Check files with extensions
                for ext in extensions:
                    file_url = urljoin(target_url, word + '.' + ext)
                    url_queue.put(('file', word + '.' + ext, file_url))

            # Start worker threads
            threads = []
            for i in range(min(self.max_threads, len(words))):
                t = threading.Thread(target=self._worker, args=(url_queue, result_queue))
                t.daemon = True
                t.start()
                threads.append(t)

            # Wait for completion
            url_queue.join()

            # Collect results
            while not result_queue.empty():
                result_type, path, url, status_code, content_length = result_queue.get()

                if result_type == 'dir' and status_code in [200, 301, 302, 403]:
                    results['directories'].append({
                        'path': path,
                        'url': url,
                        'status': status_code,
                        'size': content_length
                    })
                elif result_type == 'file' and status_code == 200:
                    results['files'].append({
                        'path': path,
                        'url': url,
                        'status': status_code,
                        'size': content_length
                    })

        except Exception as e:
            results['errors'].append(str(e))

        return results

    def _worker(self, url_queue, result_queue):
        """Worker thread for checking URLs"""
        while True:
            try:
                result_type, path, url = url_queue.get(timeout=1)

                try:
                    response = requests.head(url, timeout=self.timeout, allow_redirects=False)
                    content_length = response.headers.get('content-length', '0')

                    result_queue.put((result_type, path, url, response.status_code, content_length))

                except requests.RequestException:
                    # If HEAD fails, try GET
                    try:
                        response = requests.get(url, timeout=self.timeout, allow_redirects=False)
                        content_length = len(response.content) if response.content else '0'
                        result_queue.put((result_type, path, url, response.status_code, content_length))
                    except:
                        pass

                url_queue.task_done()

            except queue.Empty:
                break

    def _get_default_wordlist(self):
        """Get default wordlist path or create one"""
        default_words = [
            'admin', 'administrator', 'login', 'logon', 'signin', 'auth',
            'backup', 'backups', 'bak', 'old', 'new', 'test', 'testing',
            'dev', 'development', 'staging', 'prod', 'production',
            'config', 'configuration', 'settings', 'setup',
            'upload', 'uploads', 'files', 'images', 'img', 'pics', 'photos',
            'css', 'js', 'javascript', 'scripts', 'assets', 'static',
            'api', 'rest', 'graphql', 'soap', 'xml', 'json',
            'db', 'database', 'sql', 'mysql', 'postgres', 'mongodb',
            'phpmyadmin', 'adminer', 'webmail', 'mail', 'email',
            'ftp', 'ssh', 'ssl', 'tls', 'cert', 'certificate',
            'log', 'logs', 'error', 'access', 'debug',
            'tmp', 'temp', 'cache', 'session', 'sessions',
            'user', 'users', 'member', 'members', 'profile', 'profiles',
            'dashboard', 'panel', 'control', 'cpanel', 'plesk',
            'status', 'health', 'info', 'information', 'about',
            'contact', 'help', 'support', 'faq', 'documentation',
            'wiki', 'blog', 'news', 'forum', 'forums', 'board', 'boards',
            'search', 'find', 'query', 'results',
            'home', 'index', 'main', 'default', 'welcome',
            'site', 'website', 'web', 'www', 'root',
            'public', 'private', 'internal', 'external',
            'server', 'host', 'domain', 'subdomain',
            'git', 'svn', 'cvs', '.git', '.svn', '.DS_Store',
            'wp-admin', 'wp-content', 'wp-includes', 'wordpress',
            'joomla', 'drupal', 'magento', 'shopify'
        ]

        # Create wordlist file if it doesn't exist
        wordlist_path = os.path.join(os.path.dirname(__file__), 'wordlist.txt')
        if not os.path.exists(wordlist_path):
            with open(wordlist_path, 'w') as f:
                for word in default_words:
                    f.write(word + '\n')

        return wordlist_path

    def recursive_bust(self, target_url, max_depth=2, wordlist_path=None):
        """
        Perform recursive directory busting
        Args:
            target_url: Base URL to scan
            max_depth: Maximum recursion depth
            wordlist_path: Path to wordlist file
        Returns:
            dict: Recursive busting results
        """
        results = {
            'target': target_url,
            'scan_time': datetime.now().isoformat(),
            'all_directories': [],
            'all_files': [],
            'depth_scanned': 0
        }

        scanned_urls = set()
        to_scan = [(target_url, 0)]  # (url, depth)

        while to_scan and max_depth > 0:
            current_url, depth = to_scan.pop(0)

            if depth >= max_depth or current_url in scanned_urls:
                continue

            scanned_urls.add(current_url)

            # Scan current level
            level_results = self.bust_directories(current_url, wordlist_path)

            # Add found directories to next level scan
            for dir_info in level_results.get('directories', []):
                if dir_info['status'] in [200, 301, 302]:
                    to_scan.append((dir_info['url'], depth + 1))

            # Merge results
            results['all_directories'].extend(level_results.get('directories', []))
            results['all_files'].extend(level_results.get('files', []))
            results['depth_scanned'] = max(results['depth_scanned'], depth + 1)

        return results

def format_dirbust_results(results):
    """Format directory busting results for display"""
    if 'error' in results:
        return f"Error: {results['error']}"

    output = f"Directory Busting Results for {results['target']}\n"
    output += f"Scan Time: {results['scan_time']}\n\n"

    directories = results.get('all_directories', results.get('directories', []))
    files = results.get('all_files', results.get('files', []))

    if directories:
        output += f"Found Directories ({len(directories)}):\n"
        for dir_info in sorted(directories, key=lambda x: x.get('status', 999)):
            status = dir_info.get('status', 'Unknown')
            size = dir_info.get('size', 'Unknown')
            output += f"  {status:3} {size:>8} {dir_info['url']}\n"
        output += "\n"

    if files:
        output += f"Found Files ({len(files)}):\n"
        for file_info in sorted(files, key=lambda x: x.get('status', 999)):
            status = file_info.get('status', 'Unknown')
            size = file_info.get('size', 'Unknown')
            output += f"  {status:3} {size:>8} {file_info['url']}\n"
        output += "\n"

    if not directories and not files:
        output += "No directories or files found.\n"

    if results.get('errors'):
        output += f"Errors encountered:\n"
        for error in results['errors']:
            output += f"  {error}\n"

    return output