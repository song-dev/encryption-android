package com.song.encryption;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {
    @Test
    public void addition_isCorrect() {

        String data = "sssss";
        System.out.println(data.indexOf("."));
        String substring = data.substring(0, -1);
        System.out.println("substring: "+substring+"==length: "+substring.length());
        assertEquals(4, 2 + 2);
    }
}