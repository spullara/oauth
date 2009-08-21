package net.oauth;

import java.util.ArrayList;
import java.util.List;

/**
 * Contains selected parameters from an OAuth request, in a form suitable for
 * detecting duplicate requests. The timestamp, nonce, consumer key and request
 * or access token are contained. Two objects compare equal only if all of these
 * components are equal. The timestamp is most significant for comparison.
 * <p>
 * The implementation is optimized for the comparison operations (compareTo,
 * equals and hashCode).
 */
class TimestampAndNonce implements Comparable<TimestampAndNonce> {

    private final String sortKey;

    TimestampAndNonce(long timestamp, String nonce, String consumerKey, String token) {
        List<String> etc = new ArrayList<String>(3);
        etc.add(nonce);
        etc.add(consumerKey);
        etc.add(token);
        sortKey = String.format("%20d&%s", Long.valueOf(timestamp), OAuth.percentEncode(etc));
    }

    /**
     * Construct an object that's greater than other objects whose timestamp is
     * less than the given timestamp, and less than or equal to all other
     * objects. (It's less than objects with the same timestamp and a nonce
     * etc.) This is useful for identifying stale objects, by comparing them to
     * an object with the oldest acceptable timestamp.
     */
    TimestampAndNonce(long timestamp) {
        sortKey = String.format("%20d", Long.valueOf(timestamp));
    }

    public int compareTo(TimestampAndNonce that) {
        return (that == null) ? 1 : sortKey.compareTo(that.sortKey);
    }

    @Override
    public int hashCode() {
        return sortKey.hashCode();
    }

    @Override
    public boolean equals(Object that) {
        if (that == null)
            return false;
        if (that == this)
            return true;
        if (that.getClass() != getClass())
            return false;
        return sortKey.equals(((TimestampAndNonce) that).sortKey);
    }

    @Override
    public String toString() {
        return sortKey;
    }
}
