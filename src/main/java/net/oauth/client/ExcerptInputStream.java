package net.oauth.client;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/** A decorator that retains a copy of the first few bytes of data. */
public class ExcerptInputStream extends FilterInputStream
{
    /**
     * A marker that's appended to the excerpt if it's less than the complete
     * stream.
     */
    public static final byte[] ELLIPSIS = " ...".getBytes();

    public ExcerptInputStream(InputStream in)
    {
        super(in);
    }

    private static final int LIMIT = 1024;
    private byte[] excerpt = new byte[LIMIT + ELLIPSIS.length];
    private int taken = 0; // bytes received from in
    private int given = Integer.MAX_VALUE; // bytes delivered to callers

    @Override
    public void close() throws IOException
    {
        super.close();
        trimExcerpt();
    }

    /** The first few bytes of data, plus ELLIPSIS if there are more bytes. */
    public byte[] getExcerpt() throws IOException
    {
        if (taken < excerpt.length) {
            final int mark = Math.min(given, taken);
            given = Integer.MAX_VALUE;
            while (taken < excerpt.length) {
                read(excerpt, taken, LIMIT - taken);
            }
            given = mark;
        }
        return excerpt;
    }

    @Override
    public int read(byte[] b, int offset, int length) throws IOException
    {
        if (given < taken) {
            final int e = Math.min(length, taken - given);
            if (e > 0) {
                System.arraycopy(excerpt, given, b, offset, e);
                given += e;
                if (given >= taken) {
                    given = Integer.MAX_VALUE;
                }
            }
            return e;
        }
        final int r = super.read(b, offset, length);
        if (r > 0) {
            final int e = Math.min(r, LIMIT - taken);
            if (e >= 0) {
                System.arraycopy(b, offset, excerpt, taken, e);
                taken += e;
                if (taken >= LIMIT) {
                    System.arraycopy(ELLIPSIS, 0, excerpt, LIMIT, ELLIPSIS.length);
                    taken = excerpt.length;
                }
            }
        } else if (length > 0) {
            // There's no more data to take.
            trimExcerpt();
        }
        return r;
    }

    @Override
    public int read(byte[] b) throws IOException
    {
        return read(b, 0, b.length);
    }

    @Override
    public int read() throws IOException
    {
        byte[] b = new byte[1];
        return (read(b) <= 0) ? -1 : unsigned(b[0]);
    }

    private void trimExcerpt()
    {
        if (taken < excerpt.length) {
            byte[] complete = new byte[taken];
            System.arraycopy(excerpt, 0, complete, 0, taken);
            excerpt = complete;
        }
    }

    private static int unsigned(byte b)
    {
        return (b >= 0) ? b : ((int) b) + 256;
    }

}
