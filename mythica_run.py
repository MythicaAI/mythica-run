#!/usr/bin/env python3

# Command line automation of the Mythica PCG process
# for Sprocket room generation
import argparse
import glob
import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from functools import partial
from http import HTTPStatus
from os import PathLike
from pathlib import Path, PurePosixPath
from time import sleep

from munch import munchify
from requests_toolbelt.multipart.encoder import MultipartEncoder

import requests
from pydantic_settings import BaseSettings
from pydantic import BaseModel, Field

from connection_pool import ConnectionPool
from log_config import log_config

log_config(log_level="DEBUG")

log = logging.getLogger(__name__)
conn = ConnectionPool()


class Settings(BaseSettings):
    """
    Application settings, can be overridden from environment or arguments
    Can be configured as
        export MYTHICA_ENDPOINT=https://api-staging.mythica.gg
        export MYTHICA_API_KEY=<your-api-key>

    Or override via the command line
    """
    mythica_endpoint: str = 'https://api.mythica.gg'
    mythica_api_key: str = ''
    mythica_job_def_id: str = 'jobdef_26dDbTDGYBu1XYSeEree23tHzvbK'  # cave generator


class ProcessResult(BaseModel):
    """Result of a single input output invocation"""
    inputs: list[str]
    output_path: PathLike
    status_code: int = HTTPStatus.OK
    status_message: str = ''


class FileRef(BaseModel):
    """Model of an uploaded file"""
    file_id: str
    file_name: str
    content_hash: str
    size: int
    already: bool
    disk_path: Path


class UploadRef(BaseModel):
    """Model of a file for uploading into a relative package path"""
    disk_path: Path
    package_path: PurePosixPath


class JobContext(BaseModel):
    """Typesafe wrapper for job execution"""
    mythica_endpoint: str
    mythica_api_key: str
    mythica_auth_token: str

    job_def_id: str = ''
    results: list[ProcessResult] = Field(default_factory=list)
    inputs: list[UploadRef] = Field(default_factory=list)
    output_path: PathLike
    job_per_input: bool

    def auth_header(self) -> dict[str, str]:
        """Provide the authorization bearer token header for web requaests"""
        return {
            f'Authorization': f'Bearer {self.mythica_auth_token}'
        }


class PackageFile(BaseModel):
    """Model of a file for uploading into a relative package path"""
    disk_path: Path
    package_path: PurePosixPath


def log_api_error(response: requests.Response):
    """
    Logs detailed information about an HTTP error from a FastAPI backend.

    Args:
        response (requests.Response): The response object returned by the `requests` library.
    """
    try:
        if response.headers.get("Content-Type", "").startswith("application/json"):
            response_body = str(response.json())
        else:
            response_body = response.text

        error_details = {
            "status_code": response.status_code,
            "url": response.url,
            "method": response.request.method,
            "response": response_body,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        error_details = {
            "status_code": response.status_code,
            "url": response.url,
            "method": response.request.method,
            "error": f"Failed to parse response details: {e}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    log.error("API error: %s", error_details)


def maybe_upload_file(context: JobContext, upload_ref: UploadRef) -> FileRef:
    """Upload a file from a package path if it's hash doesn't exist, return its asset contents"""

    # get the content hash of the input file
    page_size = 64 * 1024
    sha1 = hashlib.sha1()
    with open(upload_ref.disk_path, "rb") as file:
        while content := file.read(page_size):
            sha1.update(content)
    existing_digest = sha1.hexdigest()

    log.debug("looking for: %s with sha1: %s",
              upload_ref.package_path, existing_digest)

    # find an existing file by hash if it exists that is owned by this user
    r = conn.get(f"{context.mythica_endpoint}/v1/files/by_content/{existing_digest}",
                 headers=context.auth_header())
    # return the file_id if the content digest already exists
    if r.ok:
        o = munchify(r.json())
        log.debug("found file: %s, file_id: %s with sha1: %s",
                  o.file_name,
                  o.file_id,
                  o.content_hash)
        return FileRef(
            file_id=o.file_id,
            file_name=o.file_name,
            content_hash=o.content_hash,
            size=o.size,
            already=True,
            disk_path=upload_ref.disk_path)

    # start new upload
    log.info("uploading path: %s as: %s, sha1: %s",
             upload_ref.disk_path,
             upload_ref.package_path,
             existing_digest)

    with open(upload_ref.disk_path, 'rb') as f:
        upload_url = f"{context.mythica_endpoint}/v1/upload/store"
        m = MultipartEncoder(
            fields={'files': (str(upload_ref.package_path),
                              f, 'application/octet-stream')}
        )
        headers = {
            **context.auth_header(),
            "Content-Type": m.content_type,
        }
        r = conn.post(upload_url, headers=headers,
                      data=m.to_string(), timeout=3)
        if not r.ok:
            log_api_error(r)
            r.raise_for_status()

        o = munchify(r.json())

        # validate that we're doing digest checks correctly
        file_info = o.files[0]
        assert file_info.content_hash == existing_digest
        log.info("Uploaded: %s with size: %s, sha1: %s, file_id: %s",
                 file_info.file_name,
                 file_info.size,
                 file_info.content_hash,
                 file_info.file_id)

        return FileRef(
            file_id=file_info.file_id,
            file_name=file_info.file_name,
            content_hash=file_info.content_hash,
            size=file_info.size,
            already=False,
            disk_path=upload_ref.disk_path)


def as_posix_path(path: str) -> PurePosixPath:
    """Convert string paths to explicitly posix paths for package relative paths"""
    return PurePosixPath(Path(path).as_posix())


def upload_from_path(
        context: JobContext,
        root_path: Path,
        files_directory: str) -> list[FileRef]:
    """Given a root path, upload all of the files in that directory"""
    files = []
    scan_path = os.path.join(root_path, files_directory)
    for root, dirs, file_listing in os.walk(scan_path):
        for file in file_listing:
            abs_path = Path(os.path.abspath(Path(root) / file))
            package_path = as_posix_path(os.path.relpath(root_path, abs_path))
            files.append(
                UploadRef(
                    disk_path=abs_path,
                    package_path=package_path))

    # Perform the file uploads
    uploaded_files = []
    for f in files:
        uploaded_files = map(partial(maybe_upload_file, context), files)
    return uploaded_files


def build_output_path(context: JobContext, input_path: Path) -> Path:
    """Convert input path into output path"""
    output_path = input_path.name + "." + context.output_file_extension
    log.debug("writing to output_path: %s", output_path)
    return context.output_path / Path(output_path)


def track_job(context: JobContext, job_id: str):
    """Track job with given id"""
    correlations = {}
    processes = {}
    progress = 0
    started = datetime.now(timezone.utc)
    deadline = started + timedelta(minutes=3)
    while True:
        results_url = f"{context.mythica_endpoint}/v1/jobs/results/{job_id}"
        r = conn.get(results_url, headers=context.auth_header())
        log.debug(f"GET {results_url} {r.status_code}: {r.text}")
        if not r.ok:
            log_api_error(r)
            break

        job_results = munchify(r.json())
        progress = 0
        for result in job_results.results:
            result_data = result.result_data
            if result_data.job_id != job_id:
                raise ValueError(f"invalid job_id: {result_data.job_id}")
            cor = result_data.correlation
            if cor in correlations:
                # correlation already processed
                continue
            process = result_data.process_guid
            item_type = result_data.item_type
            correlations[cor] = result_data
            processes[process] = result_data
            log.info("RESULT %s %s", item_type, result)
            if item_type == 'progress':
                progress = int(result_data['progress'])

        if progress == 100:  # bug that job results report completed before job is done job_results.completed
            log.info("COMPLETED job_id: %s, path: %s, elapsed: %s",
                     job_id,
                     context.output_path,
                     datetime.now(timezone.utc) - started)
            break

        # handle job timeouts
        timestamp = datetime.now(timezone.utc)
        if timestamp > deadline:
            log.error("TIMEOUT after %s", timestamp - started)
            break

        sleep(1)

    log.info("job_id: %s, %s processes, %s correlations",
             job_id, len(processes), len(correlations))

def invoke_job_single_file_input(context: JobContext, file_ref: FileRef) -> ProcessResult:
    """Invoke a single-file job with a file_id"""
    settings = {
        'auto_del': True,
        'uni_scale': 100.0,
        'amplitude': 1.0,
        'element_size': 0.1,
        'lod_density': 0.5,
        'lod_count': 3,
        'lod1': 1.0,
        'lod2':1.0,
        'lod3':1.0,
        'lod4':1.0,
        'lod5':1.0,
    }
    url = f"{context.mythica_endpoint}/v1/jobs"
    json = {
        'job_def_id': context.job_def_id,
        'params': {
            'input0': {'file_id': file_ref.file_id},
            'auto_del': settings['auto_del'],
            'uni_scale': settings['uni_scale'],
            'amplitude': settings['amplitude'],
            'elementsize': settings['element_size'],
            'targetDensity': settings['lod_density'],
            'countLod': settings['lod_count'],
            'lod1': settings['lod1'],
            'lod2': settings['lod2'],
            'lod3': settings['lod3'],
            'lod4': settings['lod4'],
            'lod5': settings['lod5'],
            'format': 'fbx'
        }
    }

    log.debug("invoking %s, popping input %s",
              context.job_def_id, file_ref.file_id)
    r = requests.post(url, json=json, headers=context.auth_header())
    if not r.ok:
        log_api_error(r)
        r.raise_for_status()

    # track the returned job
    o = munchify(r.json())
    track_job(context, o.job_id)


def invoke_job(context):
    """Invoke the job on the mythica backend"""
    if context.job_per_input:
        # process inputs, reset and store results
        results = list(
            map(partial(invoke_job_single_file_input, context), context.inputs))
        context.inputs = []
        context.results.extend(results)
    else:
        raise ValueError("Only job-per-input is supported currently")


def process_input_path(context: JobContext, abs_input_path: Path):
    # build the abs and relative file paths
    file = os.path.basename(abs_input_path)
    package_path = as_posix_path(file)
    upload_ref = UploadRef(
        disk_path=abs_input_path,
        package_path=package_path)
    # upload the input path file
    file_ref = maybe_upload_file(context, upload_ref)
    context.inputs.append(file_ref)

    invoke_job(context)


def walk_input_path(context: JobContext, path: Path):
    for root, _, files in os.walk(path):
        for file in files:
            process_input_path(context,
                               Path(os.path.abspath(os.path.join(root, file))))


def glob_input_pattern(context: JobContext, pattern: str):
    matched_files = glob.glob(pattern, recursive=True)
    for file_path in matched_files:
        if os.path.isfile(file_path) and file_path.lower().endswith('.fbx'):
            process_input_path(context,
                               Path(os.path.abspath(file_path)))


def report(context: JobContext):
    """Log the results of the execution against the API"""
    for r in context.results:
        log.info("%s -> %s, result: %s (%s)",
                 r.input_fbx_path,
                 r.output_fbx_path,
                 r.status_code,
                 r.status_message)
    else:
        log.error("no results")


def process_inputs(context: JobContext, inputs: list[str]):
    """Given the raw array of inputs from the command line, handle various input types"""
    for input in inputs:
        if input.index('*'):
            glob_input_pattern(context, input)
        elif os.path.isdir(input):
            walk_input_path(context, Path(input))
        elif os.path.exists(input):
            process_input_path(context, Path(input))
        else:
            log.error("input: %s is not a path, directory or file", input)

    # Nothing has run so far, run the collected inputs against the job
    if not context.job_per_input:
        invoke_job(context)

    report(context)


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Invoke a job from the Mythica backend with some input files.')
    parser.add_argument(
        '--input-file', '-i',
        dest='input',
        nargs='+',
        required=True,
        help="Add input files or input file patterns to the job invocation, if the job requires ordered inputs use explicit file paths")
    parser.add_argument(
        '--output-path', '-o',
        help="Set the output path for the invokation - by default it will be the current working directory",
        required=False,
        default=os.getcwd())
    parser.add_argument(
        "--job-per-input", '-1',
        required=False,
        default=True,
        action='store_true',
        help="Run a job per input, else run all inputs against a single job"
    )
    parser.add_argument(
        "--endpoint", "-e",
        required=False,
        default=None,
        help="Endpoint to use for invoking the job, See https://api-staging.mythica.gg for bleeding edge"
    )
    parser.add_argument(
        "--key", "-k",
        required=False,
        default=None,
        help="Mytica API Key. Create here - https://api.mythica.gg/api-keys"
    )
    parser.add_argument(
        "--job_def", '-j',
        required=False,
        default='',
        help="Job definition to use, if any"
    )

    return parser.parse_args()


def start_session(endpoint: str, key: str) -> str:
    """Using a Mythica API key, start a new session returning the authentication token"""
    r = conn.get(f"{endpoint}/v1/sessions/key/{key}")
    if not r.ok:
        log_api_error(r)
    r.raise_for_status()
    o = munchify(r.json())
    if not o.get('token'):
        raise KeyError(
            "token missing from session response %s %s", r.status_code)
    token = o.token
    return token


def init_context(context: JobContext):
    """Do any specific initialization around the context values"""
    if not os.path.exists(context.output_path):
        os.makedirs(context.output_path)
        log.info(f"created output directory: %s", context.output_path)


def main():
    """Entrypoint"""
    args = parse_args()
    settings = Settings()

    # do argument overrides of env variables
    endpoint = args.endpoint or settings.mythica_endpoint
    key = args.key or settings.mythica_api_key
    job_def_id = args.job_def or settings.mythica_job_def_id

    if key is None:
        raise ValueError("no --key or MYTHICA_API_KEY set")

    start_session(endpoint, key)
    context = JobContext(
        mythica_endpoint=endpoint,
        mythica_api_key=key,
        mythica_auth_token=start_session(endpoint, key),
        job_def_id=job_def_id,
        results=[],
        output_path=Path(args.output_path),
        job_per_input=args.job_per_input)
    init_context(context)
    process_inputs(context, args.input)


if __name__ == '__main__':
    main()
