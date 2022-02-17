package kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.utility;

@FunctionalInterface
public interface PatternMatchingFunction {
    public void matchPattern(String pattern) throws Exception;
}
