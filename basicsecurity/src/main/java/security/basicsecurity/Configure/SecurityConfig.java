package security.basicsecurity.Configure;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration // 설정파일 이므로 Configuration 어노테이션 설정
@EnableWebSecurity // 스프링 시큘리티의 동작과 관련된 클래스 파일들을 임포트 시켜 동작시키는 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // 스프링 시큐리티의 웹 보안 기능을 초기화 및 설정하는 WebSecurityConfigurerAdapter 클래스
    // 세부적 보안기능을 설정할수 있는 API 인 HttpSecurity를 제공한다.


    @Override // 보안 기능을 설정하는 configure 레이션을 재정의 하여 설정, 재정의 안하면 기본 설정으로 동작
    protected void configure(HttpSecurity http) throws Exception {
        http // 인가정책 설정 - 기능에 대하여 접근이 가능한지를 판별
                .authorizeRequests() // 요청에 대한 보안검사 (권한 검사 실시) ( 동작조건 )
                .anyRequest() // 모든 요청에 대하여 실행 ( 필터조건 )
                .authenticated(); // 인증을 받아야함 ( 필요조건 )

        http // 인증정책 설정 - 기능에 접근이 가능한지를 검증
                .formLogin(); // 폼 로그인 으로 설정
    }
}
