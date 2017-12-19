#!/usr/bin/env python

# This script contains jira related utilties for Jenkins.

from collections import defaultdict
import logging
import re
import click
from jira import JIRA, JIRAError

logging.basicConfig()
LOGGER = logging.getLogger("jirautils")

# Cache of done transitions per project, saves looking this up for
# every issue
transitions = {}


@click.group()
@click.option('--user',
              help="Jira User",
              required=True)
@click.option('--password',
              help="Jira Password",
              required=True)
@click.option('--instance', 'jira_instance',
              help="Jira instance url",
              default="https://rpc-openstack.atlassian.net")
@click.option('--debug/--no-debug', default=False)
def cli(user, password, jira_instance, debug):
    click.get_current_context().obj = \
        JIRA(jira_instance, basic_auth=(user, password))
    if debug:
        LOGGER.setLevel(logging.DEBUG)


def issues_for_query(query):
    ctx = click.get_current_context()
    authed_jira = ctx.obj
    LOGGER.debug("Looking for issues matching query: {q}".format(q=query))
    try:
        issues = sorted(authed_jira.search_issues(query),
                        key=lambda i: int(i.id))
        LOGGER.debug("Issues returned by query: {}".format(
            [i.key for i in issues]))
        return issues
    except JIRAError as e:
        LOGGER.critical("Error querying for issues, bad JQL?"
                        " Query: {q}, Error: {e}"
                        .format(q=query, e=e))
        ctx.exit(1)


@cli.command()
@click.option('--query')
def query(query):
    """Print keys for issues that match a query."""
    for issue in issues_for_query(query):
        click.echo(issue.key)


def get_label_query_terms(labels):
    terms = []
    for label in labels:
        terms.append("labels = \"{label}\"".format(label=label))
    return " AND ".join(terms)


@cli.command()
@click.option('--project')
@click.option('--status', default="BACKLOG")
@click.option('--label',
              'labels',
              help="labels an issue must match,"
                   " or labels to add to a new issue",
              multiple=True,
              default=["jenkins-build-failure"])
@click.option('--description')
@click.option('--summary')
def get_or_create_issue(project, status, labels, description, summary):
    """Get existing issue or create new issue.

    Note that existing issues are matched on labels, project and status,
    not summary or description.
    """
    ctx = click.get_current_context()
    issue = None

    # Check for existing issues
    query = ("{label_terms} AND project = \"{p}\" AND status = {s}"
             .format(label_terms=get_label_query_terms(labels),
                     p=project, s=status))
    issues = issues_for_query(query)
    if len(issues) == 1:
        issue = issues[0]
        LOGGER.debug("Found existing issue: {ik}".format(ik=issue.key))
    elif len(issues) > 1:
        issue = issues[0]
        LOGGER.debug("Query: {q} Returned >1 issues: {il}. "
                     "Will use the oldest issue {i}".format(
                        q=query,
                        il=",".join(i.key for i in issues),
                        i=issue))

    # No matching issue found, create a new one
    if not issue:
        issue = ctx.invoke(
            create_issue,
            summary=summary,
            description=description,
            project=project,
            labels=labels)
    else:
        # Shouldn't print issue key if create_issue is called as that
        # also prints the issue key.
        click.echo(issue.key)
    return issue


@cli.command()
@click.option('--project')
@click.option('--job-name', help="Name of the job")
@click.option('--job-url', help="URL of the job")
@click.option('--build-tag',
              help="Build Tag (string the identifies the job and build.)")
@click.option('--build-url', help="URL of the build")
def build_failure_issue(project, job_name, job_url, build_tag, build_url):
    """Create issue for build failure.

    1) Identify or create an issue relating to the Job that failed.
    2) Add a comment to the issue linking to the Build that failed.
    """
    ctx = click.get_current_context()
    authed_jira = ctx.obj

    issue = ctx.invoke(
        get_or_create_issue,
        project=project,
        status="BACKLOG",
        labels=["jenkins-build-failure", "jenkins", job_name],
        summary="JBF: {jn}".format(jn=job_name),
        description="The following job failed a build: [{jn}|{ju}]"
                    .format(jn=job_name, ju=job_url))

    # Whether the issue was found or created, we now have an issue relating
    # to the job. The next step is to add a comment linking to the specific
    # build failure.

    comment = "Build Failure: [{bt}|{bu}]".format(
        bt=build_tag,
        bu=build_url
    )
    authed_jira.add_comment(issue.key, comment)
    LOGGER.debug("Added comment to {ik}: \"{c}\"".format(
        ik=issue.key, c=comment))
    click.echo(issue.key)
    return issue


@cli.command()
@click.option('--summary',
              help='Issue summary',
              required=True)
@click.option('--description',
              help='Issue description/body',
              required=True)
@click.option('--project',
              help='Jira Project Key',
              required=True)
@click.option('--type', 'issue_type',
              help="Jira issue type",
              default="Task")
@click.option('--label',
              'labels',
              help="Add label to issue, can be specified multiple times",
              multiple=True,
              default=["jenkins-build-failure"])
def create_issue(summary, description, project, issue_type, labels):
    """Create a Jira Issue."""
    ctx = click.get_current_context()
    authed_jira = ctx.obj

    LOGGER.debug("Creating new issue")
    issue = authed_jira.create_issue(
        project=project,
        summary=summary,
        description=description,
        issuetype={'name': issue_type},
        labels=labels
    )
    click.echo(issue.key)
    return issue


def find_done_transition(authed_jira, issue):
    """Find the final state for an issue.

    Each project can have a different set of states. In order to close issues
    we have to determine the correct final state. This function finds the
    transition to the end state and caches that per project.
    """
    try:
        return transitions[issue.fields.project.key]
    except KeyError:
        issue_transitions = authed_jira.transitions(issue)
        done_transition = [t for t in issue_transitions
                           if t['to']['statusCategory']['key'] == 'done'][0]
        transitions[issue.fields.project.key] = done_transition
        return done_transition


@cli.command()
@click.option('--issue', required=True)
def close(issue):
    ctx = click.get_current_context()
    authed_jira = ctx.obj
    try:
        issue = authed_jira.issue(issue)
        done_transition = find_done_transition(authed_jira, issue)
        authed_jira.transition_issue(
            issue,
            done_transition['id'])
    except JIRAError as e:
        click.echo("Error closing issue {i}: {e}".format(i=issue, e=e.message))
        ctx.exit(1)


@cli.command()
@click.option('--query', required=True)
def close_all(query):
    ctx = click.get_current_context()
    authed_jira = ctx.obj
    try:
        issues = issues_for_query(query)
        for issue in issues:
            done_transition = find_done_transition(authed_jira, issue)
            authed_jira.transition_issue(
                issue,
                done_transition['id'])
    except JIRAError as e:
        click.echo("Error closing issue {i}: {e}".format(i=issue, e=e.message))
        ctx.exit(1)


@cli.command()
@click.option('--issue')
@click.option('--label', 'labels', multiple=True)
def set_labels(issue, labels):
    ctx = click.get_current_context()
    authed_jira = ctx.obj
    try:
        issue = authed_jira.issue(issue)
        issue.labels = labels
    except JIRAError:
        click.echo("Failed to find issue {}".format(issue))
        ctx.exit(1)


@cli.command()
@click.option('--issue')
def comments(issue):
    ctx = click.get_current_context()
    authed_jira = ctx.obj
    try:
        issue = authed_jira.issue(issue)
        for comment in issue.fields.comment.comments:
            click.echo(comment.body)
    except JIRAError:
        click.echo("Failed to find issue {}".format(issue))
        ctx.exit(1)


@cli.command()
@click.option("--squash/--no-squash",
              help="Squash duplicate issues")
def findfailuredupes(squash):
    """Find duplicate build failure issues.

    Jenkins used to create a new issue for every build failure. This is no
    longer the case as now when repeat job failures occur if an issue already
    exists in the backlog it will be updated instead of duplicated.

    This function is for finding and cleanup up duplicates left over from
    the previous methodology.
    """
    ctx = click.get_current_context()
    authed_jira = ctx.obj
    issues = authed_jira.search_issues(
        "labels = jenkins-build-failure and status = BACKLOG")
    jobs = defaultdict(list)
    for issue in issues:
        match = re.match("^JBF*:\s*(.*)-[0-9]+$", issue.fields.summary)
        if match:
            job = match.group(1)
            jobs[job].append(issue)
        else:
            print "non matching summary: {}".format(issue.fields.summary)
    duplicates = {job: sorted(issues, key=lambda x: int(x.id))
                  for job, issues in jobs.items()
                  if len(issues) > 1}
    if duplicates:
        print "Duplicates:"
        for job, issues in duplicates.items():
            print "{job} --> {issues}".format(
                job=job, issues=", ".join(i.key for i in issues))
        if squash:
            print "Squashing duplicates"
            for job, issues in duplicates.items():
                master_issue = issues.pop(0)
                print "{job} / {master}".format(job=job, master=master_issue)
                for duplicate_issue in issues:
                    print "  Adding Comment: {}".format(duplicate_issue.key)
                    authed_jira.add_comment(
                        duplicate_issue.key,
                        "Closing as duplicate of {m}".format(
                            m=master_issue.key))
                    transition = find_done_transition(authed_jira,
                                                      duplicate_issue)
                    print "  Transitioning: {k} --> {t}".format(
                        k=duplicate_issue.key, t=transition['name'])
                    authed_jira.transition_issue(
                        duplicate_issue,
                        transition['id'])
            print "Squash Complete"
        else:
            print "Squash disabled, leaving duplicates"
    else:
        print "No Duplicates Found"


if __name__ == "__main__":
    cli()
