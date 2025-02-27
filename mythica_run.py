#!/usr/bin/env python3

# Command line automation of the Mythica job API

import argparse
import glob
import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from functools import partial
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
supported_formats = {'.fbx', '.obj', '.usd', '.png', '.jpg', '.jpeg', '.tiff', '.dxt'}

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
    # cave generator
    mythica_job_def_id: str = 'jobdef_26dDbTDGYBu1XYSeEree23tHzvbK'


class JobResult(BaseModel):
    """Result of a single input output invocation"""
    job_def_id: str
    job_id: str
    inputs: list[str]
    output_path: PathLike
    duration_seconds: float = 0
    num_processes: int = 0
    num_messages: int = 0
    messages: list[str] = Field(default_factory=list)
    meshes: list[PathLike] = Field(default_factory=list)
    progress: int = 0
    state: str = None


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
    results: list[JobResult] = Field(default_factory=list)
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
        response (requests.Response): The response object returned by the
        `requests` library.
    """
    try:
        content_type = response.headers.get("Content-Type", "")
        if content_type.startswith("application/json"):
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
    """Upload a file from a package path if it's hash doesn't exist, return
    its asset contents"""

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
    by_content = (f"{context.mythica_endpoint}/v1/files/"
                  f"by_content/{existing_digest}")
    r = conn.get(by_content,
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
    """Convert string paths to explicitly posix paths for
    package relative paths"""
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


def download_meshes(context: JobContext, mesh_file_ids: list[str]) -> list[PathLike]:
    """Download all meshes and return the disk paths"""
    downloaded_files = []
    for mesh_file_id in mesh_file_ids:
        download_path = download_file(
            context.mythica_endpoint,
            str(context.output_path),
            mesh_file_id,
            context.auth_header())
        log.info("downloaded %s to %s", mesh_file_id, download_path)
        downloaded_files.append(Path(download_path))
    return downloaded_files


def download_file(endpoint: str, directory: str, file_id: str, headers=None) -> str:
    """Get the URL to download the file"""
    url = f"{endpoint}/v1/download/info/{file_id}"
    r = requests.get(url, headers=headers or {})
    if not r.ok:
        log_api_error(r)
        r.raise_for_status()

    doc = r.json()

    # Download the file
    file_name = file_id + "_" + doc['name'].replace('\\', '_').replace('/', '_')
    file_path = os.path.join(directory, file_name)

    downloaded_bytes = 0
    with open(file_path, "w+b") as f:
        download_req = requests.get(doc['url'], stream=True, headers=headers)
        chunk_size = 1024 * 64
        for chunk in download_req.iter_content(chunk_size=chunk_size):
            if chunk:
                downloaded_bytes += len(chunk)
                f.write(chunk)

    return file_path

def track_job(context: JobContext, job_id: str, inputs: list[FileRef]) -> JobResult:
    """Track job with given id"""
    correlations = {}
    processes = {}
    mesh_file_ids = set()
    progress = 0
    state = 'started'
    started = datetime.now(timezone.utc)
    deadline = started + timedelta(minutes=3)
    message_log = []
    while True:
        results_url = f"{context.mythica_endpoint}/v1/jobs/results/{job_id}"
        r = conn.get(results_url, headers=context.auth_header())
        log.debug(f"GET {results_url} {r.status_code}: {r.text}")
        if not r.ok:
            log_api_error(r)
            state = 'failed-http-request'
            break

        job_results = munchify(r.json())
        progress = 0
        for result in job_results.results:
            result_data = result.result_data
            if result_data.job_id != job_id:
                raise ValueError(f"invalid job_id: {result_data.job_id}")
            cor = result_data.correlation
            for mesh_file_id in result_data.get('files', {}).get('mesh', []):
                mesh_file_ids.add(mesh_file_id)

            if cor in correlations:
                # correlation already processed
                # todo: fix correlation bug with file/progress overlapping
                continue
            process = result_data.process_guid
            item_type = result_data.item_type
            message_log.append(json.dumps(result_data))
            correlations[cor] = result_data
            processes[process] = result_data
            log.info("RESULT %s %s", item_type, result)
            if item_type == 'progress':
                progress = int(result_data['progress'])

        if job_results.completed:
            log.info("COMPLETED job_id: %s, path: %s, elapsed: %s",
                     job_id,
                     context.output_path,
                     datetime.now(timezone.utc) - started)
            state = 'completed'
            break

        # handle job timeouts
        timestamp = datetime.now(timezone.utc)
        if timestamp > deadline:
            log.error("TIMEOUT after %s", timestamp - started)
            state = 'job-timed-out'
            break

        sleep(1)

    log.info("job_id: %s - %s - %s processes, %s meshes",
             job_id, state, len(processes), len(mesh_file_ids))

    mesh_paths = download_meshes(context, list(mesh_file_ids))
    duration = (datetime.now(timezone.utc) - started).total_seconds()
    input_names = [str(x.disk_path) for x in inputs]
    return JobResult(
        job_def_id=context.job_def_id,
        job_id=job_id,
        inputs=input_names,
        output_path=context.output_path,
        duration_seconds=duration,
        messages=message_log,
        meshes=mesh_paths,
        progress=progress,
        num_processes=len(processes),
        num_messages=len(correlations),
        state=state)


def invoke_job_single_file_input(
        context: JobContext,
        file_ref: FileRef) -> JobResult:
    """Invoke a single-file job with a file_id"""

    # TODO: make dynamic
    settings = {
        'auto_del': True,
        'uni_scale': 100.0,
        'amplitude': 2.0,
        'element_size': 12.0,
        'lod_density': 23.0,
        'lod_count': 5,
        'lod1': 60.0,
        'lod2': 30.0,
        'lod3': 15.0,
        'lod4': 7.5,
        'lod5': 4.0,
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
    return track_job(context, o.job_id, [file_ref])


def invoke_job(context):
    """Invoke the job on the mythica backend"""
    if context.job_per_input:
        # process inputs, reset and store results
        results = list(
            map(partial(invoke_job_single_file_input, context),
                context.inputs))
        context.inputs = []
        context.results.extend(results)
    else:
        raise ValueError("Only job-per-input is supported currently")


def build_converted_path(abs_input_path: PathLike):
    path, ext = os.path.splitext(abs_input_path)
    return os.path.join(path, '.usd')


def process_input_path(context: JobContext, abs_input_path: Path):
    _, ext = os.path.splitext(abs_input_path)
    if ext not in supported_formats:
        raise ValueError(f"unsupported file format {ext} importing {abs_input_path}")

    # first convert if necessary
    # if not str(abs_input_path).endswith('usd'):
    #     output_usd_path = build_converted_path(abs_input_path)
    #     convert_to_usd(abs_input_path, output_usd_path)
    #     log.info("swapping converted %s for %s", output_usd_path, abs_input_path)
    #     abs_input_path = output_usd_path

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
    """Given a pattern, process each file matching the pattern"""
    matched_files = glob.glob(pattern, recursive=True)
    for file_path in matched_files:
        if os.path.isfile(file_path):
            process_input_path(context,
                               Path(os.path.abspath(file_path)))


def report(context: JobContext):
    """Log the results of the execution against the API"""
    for r in context.results:
        log.info("[%s] [%s] %s -> %s",
                 r.job_id,
                 r.state,
                 r.inputs,
                 r.meshes)
        for m in r.messages:
            log.info("[%s] %s",r.job_id, m)


def process_inputs(context: JobContext, inputs: list[str]):
    """Given the raw array of inputs from the command line,
    handle various input types"""
    for input in inputs:
        if input.find('*') > -1:
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
        description="Run a job on the Mythica infrastructure.")
    parser.add_argument(
        '--input-file', '-i',
        dest='input',
        nargs='+',
        required=True,
        help=("Add input files or input file patterns to the job invocation,"
              "if the job requires ordered inputs use explicit file paths"))
    parser.add_argument(
        '--output-path', '-o',
        help=("Set the output path for the invokation - "
              "by default it will be the current working directory"),
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
        help=("Endpoint to use for invoking the job."
              "See https://api-staging.mythica.gg for bleeding edge")
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
    """Using a Mythica API key, start a new session returning the
    authentication token"""
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
        log.info("created output directory: %s", context.output_path)


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
