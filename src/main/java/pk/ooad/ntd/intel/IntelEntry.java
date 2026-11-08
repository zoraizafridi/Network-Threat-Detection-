package pk.ooad.ntd.intel;

import pk.ooad.ntd.domain.Severity;

/**
 * One line of a threat feed: an address or network, a label, and how serious a
 * match is.
 *
 * @param cidr     the entry as written in the feed, kept for the alert text
 * @param label    who or what the address is believed to be
 * @param severity how seriously to treat a match
 * @param source   which feed the line came from
 */
public record IntelEntry(String cidr, String label, Severity severity, String source) {
}
