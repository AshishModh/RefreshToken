package Repository;


import Model.UserInfo;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

public class UserDAO {

    private JdbcTemplate template;

    public UserDAO(JdbcTemplate template) {
        this.template = template;
    }

    public UserInfo getUserInfo(String username) {
        String sql = "SELECT u.emailid email, u.name name, u.password pass, a.authority role FROM USERDATA u INNER JOIN AUTHORITIES a ON u.name = a.name WHERE " +
                "u.enabled=1 and u.emailid=?";
        UserInfo userInfo = template.queryForObject(sql, new Object[]{username},
                new RowMapper<UserInfo>() {
                    @Override
                    public UserInfo mapRow(ResultSet rs, int rowNum) throws SQLException {
                        UserInfo user = new UserInfo();
                        user.setUsername(rs.getString("email"));
                        user.setPassword(rs.getString("pass"));
                        user.setRole(rs.getString("role"));

                        return user;
                    }
                });
        return userInfo;
    }



}
