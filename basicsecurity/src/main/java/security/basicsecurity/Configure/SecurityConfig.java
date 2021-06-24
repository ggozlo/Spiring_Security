package security.basicsecurity.Configure;


import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;


@Configuration
@EnableWebSecurity
@Order(0)
// 다수의 시큐리티 설정 클래스가 있다면 순서를 지정해야함, Top-Down 방식으로 FilterChainProxy 클래스가 참조 하므로
// 매칭되는 url 정보가 넓고 포괄적일수록 후순위로 지정해야 한다.
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    /*
    * Authentication (인증, 인증주체) : 자신이 누구인이 증명하는 것
    * 사용자의 인증 정보를 저장하는 토큰 개념
    * 인증 시 id, pw를 담고 인증 검증을 위해 전달되어 사용
    * 인증후 인증결과 ( 사용자 객체, 권한 ) 를 담아서 SecurityContext 에 저장되어 전역적 참조가 가능
    *  Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    *  전역적으로 인증 결과 참조, 사용 가능
    * Authentication 객체 : principal(사용자 아이디 또는 사용자 객체, Object), credentials(사용자 패스워드),
    * authorities(인증된 사용자 권한 목록), details(인증 부가 정보), authenticated(인증 여부부
    *
    *  SecurityContext
    *  TheadLocal  > SecurityContext > Authentication > User
    * TheadLocal : 각 쓰레드에 할당된 저장소, 다른 쓰레드와 공유 x , 아무곳에서나 참조가 가능함 (전역적으로 존재한다)
    * 인증 완료시 HttpSession 에 저장되어 어플리케이션 전반에서 참조 가능
    *
    * SecurityContextHolder
    * SecurityContext 객체의 저장 방식을 설정 할수 있게 함, 래핑하는듯?
    * 전약은 스레드당 하나(기본값), 자식 스레드에 동일한 컨텍스트를 유지하는 상속전략
    *  static 으로 응용 프로그램 전역에서 하나만 저장하는 전략.
    * SecurityContextHolder.clearContext() 로 기존 정보 초기화 가능 - SecurityContext, Authentication 초기화됨
    * */

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/admin/**")
                .authorizeRequests()
                .anyRequest()
                .authenticated()
            .and()
                .httpBasic()
        ;

    }
}

@Configuration
@Order(1)
class SecurityConfig2 extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin();

        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        // 시큐리티 컨텍스트 홀더의 전략 설정도 웹보안설정어댑터 를 상소받은 설정클래스의 설정 메서드에서 설정한다
    }
}
