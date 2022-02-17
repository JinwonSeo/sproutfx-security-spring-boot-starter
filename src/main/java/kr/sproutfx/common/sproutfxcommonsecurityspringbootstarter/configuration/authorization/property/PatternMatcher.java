package kr.sproutfx.common.sproutfxcommonsecurityspringbootstarter.configuration.authorization.property;

import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class PatternMatcher {
    List<String> patterns;
}
