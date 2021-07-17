import setproctitle

from networking_wireguard import constants
from networking_wireguard.ml2.agent import wg_agent


def main():
    proctitle = "%s (%s)" % (
        constants.AGENT_PROCESS_WG,
        setproctitle.getproctitle(),
    )
    wg_agent.main()
