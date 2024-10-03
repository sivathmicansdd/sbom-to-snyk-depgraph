import typer
import json
import time
import sys
import re
import logging
import requests
from uuid import UUID
from cyclonedx.model.bom import Bom
from snyk import SnykClient
from snyk_depgraph import DepGraph
from typing import Optional
from typing import List
from semver.version import Version

# set up logging
logger = logging.getLogger(__name__)
FORMAT = "[%(filename)s:%(lineno)4s - %(funcName)s ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.WARN)

# ===== GLOBALS =====

app = typer.Typer(add_completion=False)

# globals
g = {}
DEPGRAPH_BASE_TEST_URL = "/test/dep-graph?org="
DEPGRAPH_BASE_MONITOR_URL = "/monitor/dep-graph?org="

dep_graph = None

visited = []
visited_temp = []
ignored_deps = []
dep_path_counts = {}
latest_package_version = {}

# future use
# transitive_closures = []

# ===== METHODS =====


@app.callback()
def main(
    ctx: typer.Context,
    sbom_file: str = typer.Option(
        ..., envvar="SBOM_FILE", help="Full path to SBOM file"
    ),
    prune_repeated_subdependencies: bool = typer.Option(
        False,
        help="Use if too many repeated sub dependencies causes test or monitor to fail",
    ),
    ignore_file: str = typer.Option(None, help="Full path to ignore file"),
    package_source: str = typer.Option(None, help="Type of package manager, overrides auto-detect"),
    root_node: str = typer.Option(None, help="Set or override root_node"),
    project_name: str = typer.Option(None, help="project name in Snyk UI"),
    debug: bool = typer.Option(False, help="Set log level to debug"),
):
    """Entrypoint into typer CLI handling"""

    global ignored_deps
    global dep_graph
    global visited
    global visited_temp

    if debug:
        logger.debug("*** DEBUG MODE ENABLED ***", file=sys.stderr)
        logger.setLevel(logging.DEBUG)
        logger.debug(f"\n\nProcessing MetaData\n")

    if ignore_file:
        with open(ignore_file) as data:
            ignored_deps = list(filter(None, data.read().split("\n")))

    logger.debug("sbom_file: " + sbom_file)
    with open(sbom_file) as input_json:
        g["sbom"] = Bom.from_json(data=json.loads(input_json.read()))

        #no user-defined package_source, try to auto-detect
        if package_source is None:
            package_source = get_package_manager_from_sbom()

        if package_source is None:
            typer.echo("No package source defined or detected (tried purl and name for pkg:<package manager>)", file=sys.stderr)
            sys.exit(1)
        
        logger.debug("package_source: " + package_source)
        dep_graph = DepGraph(package_source, False)

        #get latest version of all packages 
        for dependency in g["sbom"].dependencies:
            get_latest_package_versions(parent_component_ref=str(dependency.ref), depth=0, parent_nodes=[])

        visited = []
        visited_temp = []

        #figure out what root node is, it *should* be purl or name
        if root_node is None: 
            root_component_ref = "unknown"
            if g["sbom"]._metadata.component.purl:
                root_component_ref = f"{str(g['sbom']._metadata.component.purl)}"
                logger.debug(f"Setting root node to {root_component_ref} from sbom component purl")
            elif g["sbom"]._metadata.component.name:
                root_component_ref = f"{str(g['sbom']._metadata.component.name)}"
                logger.debug(f"Setting root node to {root_component_ref} from sbom component name")
        else : 
            root_component_ref = root_node 
            logger.debug(f"Setting root node to {root_node} from CLI argument!")

        sbom_to_depgraph(parent_component_ref=root_component_ref, depth=0, parent_nodes=[])

        if prune_repeated_subdependencies:
            logger.info("Pruning graph ...")
            time.sleep(2)
            prune()

        if project_name:
            logger.debug("renaming nodes to: " + project_name)
            dep_graph.rename_depgraph(project_name)

    return


@app.command()
def print_graph():
    """
    Print Snyk depGraph representation of SBOM
    """
    # dep_graph: DepGraph = g['dep_graph']

    typer.echo(f"{json.dumps(dep_graph.graph(), indent=4)}")

    return


@app.command()
def test(
    snyk_token: str = typer.Option(
        None, envvar="SNYK_TOKEN", help="Please specify your Snyk token"
    ),
    snyk_org_id: str = typer.Option(
        None,
        envvar="SNYK_ORG_ID",
        help="Please specify the Snyk ORG ID to run commands against",
    ),
):
    """
    Test SBOM with Snyk
    """
    snyk_client = SnykClient(snyk_token)
    response: requests.Response = snyk_client.post(
        f"{DEPGRAPH_BASE_TEST_URL}{snyk_org_id}", body=dep_graph.graph()
    )

    json_response = response.json()
    print(json.dumps(json_response, indent=4))

    if str(json_response["ok"]) == "False":
        typer.echo("exiting with code 1", file=sys.stderr)
        sys.exit(1)

    return


@app.command()
def monitor(
    snyk_token: str = typer.Option(
        None, envvar="SNYK_TOKEN", help="Please specify your Snyk token"
    ),
    snyk_org_id: str = typer.Option(
        None,
        envvar="SNYK_ORG_ID",
        help="Please specify the Snyk ORG ID to run commands against",
    ),
):
    """
    Monitor SBOM with Snyk
    """        
    snyk_client = SnykClient(snyk_token)

    response: requests.Response = snyk_client.post(
        f"{DEPGRAPH_BASE_MONITOR_URL}{snyk_org_id}", body=dep_graph.graph()
    )

    json_response = response.json()
    print(json.dumps(json_response, indent=4))

    if str(json_response["ok"]) == "False":
        typer.echo("exiting with code 1", file=sys.stderr)
        sys.exit(1)

    return


# Utility Functions
# -----------------

def get_package_name_and_version(purl: str) -> List:

    package_name_and_version = dep_graph.package_name_split(purl, "@")

    if len(package_name_and_version) < 2:
        logger.debug(f"package_name_and_version {package_name_and_version} must have package@version")
        return package_name_and_version

    if package_name_and_version[1].find("?") >= 0: #remove any ?at the end
        package_name_and_version1_split = package_name_and_version[1].split("?")
        package_name_and_version[1] = f"{package_name_and_version1_split[0]}"

    if len(package_name_and_version) > 2:
        return sys.exit("too many values coming back from package_name_split")
    
    return package_name_and_version

def convert_package_name_to_key(package_name: str) -> str:
    #package_name = re.sub(r"[@:/-]","", package_name)
    return package_name

def update_package_highest_version(purl: str):
    global latest_package_version

    package_name_and_version = get_package_name_and_version(purl)
    if len(package_name_and_version) < 2:
        return
    
    if len(package_name_and_version) > 2:
        logger.debug(f"from purl {purl}")
        for item in package_name_and_version:
            logger.debug(f"item {item}")
        sys.exit("too many items in package_name_and_version from get_package_name_and_version(purl)")
        return

    package_name = package_name_and_version[0]
    package_version = package_name_and_version[1]

    package_key = convert_package_name_to_key(package_name)

    if Version.is_valid(package_version):
        if not latest_package_version.get(package_key) or not Version.is_valid(latest_package_version.get(package_key)) :
            latest_package_version[package_key] = str(package_version)
        elif Version.parse(latest_package_version.get(package_key)) < Version.parse(package_version):
            latest_package_version[package_key] = str(package_version)
    else:
        #this is not a valid semver version, so no way to compare, only set if we can
        if not latest_package_version.get(package_key):
            latest_package_version[package_key] = str(package_version)

def get_latest_package_versions(parent_component_ref: str, depth: int, parent_nodes: List[str]):
    """
    Run through sbom to find latest package verions
    """
    global visited
    global visited_temp

    update_package_highest_version(purl=parent_component_ref)

#translate reference format "pkg:npm/@<root>/http@link:../../packages/http",
def translate_link_format(package_ref: str) -> str | None:
    global latest_package_version

    if package_ref.rfind("link:../../") < 0:
        #no special format found, return original ref
        return package_ref

    k = package_ref.rfind("@")
    package_name = package_ref[:k]
    package_key = convert_package_name_to_key(package_name)

    #get latest package version
    if latest_package_version.get(package_key):
        package_latest_version = package_key + "@" + latest_package_version.get(package_key)
        return package_latest_version
    else:
        logger.debug(f"NO PACKAGE VERSION EXISTS: {package_ref}")
        package_latest_version = package_key + "@-1.-1.-1"
        return package_latest_version

def sbom_to_depgraph(parent_component_ref: str, depth: int, parent_nodes: List[str]) -> DepGraph:
    """
    Convert the CDX SBOM components to snyk depgraph to find issues
    """
    global visited
    global visited_temp

    #translate any pkg:maven and ? after version to depgraph format
    parent_dep_for_depgraph = purl_to_depgraph_dep(purl=parent_component_ref)

    # special entry for the root node of the dep graph
    if depth == 0:
        if parent_dep_for_depgraph.count("@") < 1 :
            parent_dep_for_depgraph = f"{parent_dep_for_depgraph}@0.0.0"
        logger.debug(f"setting depgraph root node to: {parent_dep_for_depgraph}")
        dep_graph.set_root_node_package(f"{parent_dep_for_depgraph}")

        logger.debug(f"\n\nProcessing Children\n")

    children = get_dependencies_from_ref(parent_component_ref)
    this_childs_parents = parent_nodes + [parent_component_ref]

    for child in children:
        #translate reference format "pkg:npm/@<root>/http@link:../../packages/http",
        child = translate_link_format(child)

        depgraph_dep = purl_to_depgraph_dep(purl=str(child))

        dep_graph.add_pkg(depgraph_dep)
        increment_dep_path_count(depgraph_dep)
        dep_graph.add_dep(
            child_node_id=depgraph_dep, parent_node_id=parent_dep_for_depgraph
        )

        visited_temp.append(parent_component_ref)

        # if we've already processed this subtree, then just return
        if child not in visited and child not in this_childs_parents:
            sbom_to_depgraph(str(child), depth=depth + 1, parent_nodes=this_childs_parents)
        if child in this_childs_parents:
            logger.debug(f"child {child} already processed in parent_nodes - cyclic reference")

    # we've reach a leaf node and just need to add an entry with empty deps array
    if len(children) == 0:
        dep_graph.add_dep(child_node_id=None, parent_node_id=parent_dep_for_depgraph)
        visited.extend(visited_temp)

        visited_temp = []


def get_dependencies_from_ref(dependency_ref) -> List:
    global ignored_deps
    children = []
    for dependency in g["sbom"].dependencies:
        if str(dependency.ref) == dependency_ref:
            if ignored_deps:
                children.extend(
                    [
                        str(x.ref)
                        for x in dependency.dependencies
                        if not any(
                            [ignored_dep in str(x.ref) for ignored_dep in ignored_deps]
                        )
                    ]
                )
            else:
                children.extend([str(x.ref) for x in dependency.dependencies])

    return children


def increment_dep_path_count(dep: str):
    """
    Keep track of path counts in case we need to prune
    """
    global dep_path_counts

    dep_path_counts[dep] = dep_path_counts.get(dep, 0) + 1


def prune():
    global dep_graph

    for dep, instances in dep_path_counts.items():
        if instances > 2:
            logger.info(f"pruning {dep} ({instances=})")
            dep_graph.prune_dep(dep)


def purl_to_depgraph_dep(purl: str) -> str:
    """
    Convert purl format string to package@version for snyk
    """

    #see if we have a version number, if not, return?
    k = dep_graph.package_name_split(purl, "@")
    if len(k) < 2:
        logger.debug(f"no @ in purl_to_depgraph_dep, returning purl: {purl}")
        return purl

    #if we do, separate into two parts
    depgraph_dep_name = k[0]
    depgraph_dep_version = k[1]

    #if trailing ? in version, cut it out
    i = depgraph_dep_version.find("?")
    if i > 0:
        depgraph_dep_version = depgraph_dep_version[:i]

    #if we are maven, need to replace / with :
    if "pkg:maven/" in depgraph_dep_name:
        depgraph_dep_name = re.sub("pkg:([a-zA-Z0-9_-]*)/","",depgraph_dep_name)
        depgraph_dep_name = depgraph_dep_name.replace("/", ":")
    else: 
        depgraph_dep_name = re.sub("pkg:([a-zA-Z0-9_-]*)/","",depgraph_dep_name)

    #combine name and version
    depgraph_dep = depgraph_dep_name + "@" + depgraph_dep_version

    return depgraph_dep

def get_package_manager_from_sbom() -> str:
    package_manager = None

    if g["sbom"]._metadata.component.purl:
        purl = f"{str(g['sbom']._metadata.component.purl)}"
        package_manager = re.search("pkg:([a-zA-Z0-9_-]*)", purl, flags=re.IGNORECASE).group()

    if g["sbom"]._metadata.component.name and package_manager is None:
        name = f"{str(g['sbom']._metadata.component.name)}"
        package_manager = re.search("pkg:([a-zA-Z0-9_-]*)", name, flags=re.IGNORECASE).group()

    package_manager = package_manager.replace("pkg:", "")

    return package_manager

# ----- app entrypoint ------
if __name__ == "__main__":
    app()
