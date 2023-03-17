package Controller;


//import Service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@RequestMapping("/")
@Controller
public class HomeController {

    @RequestMapping("/")
    public String PrintHello(ModelMap model) {
        model.addAttribute("message", "Welcome To Home Page!!!!");
        return "HomePage";
    }

    @RequestMapping(path = "/public", method = RequestMethod.GET)
    public String publicPage(ModelMap map){
        map.addAttribute("message","This is public page");
        return "PublicPage";
    }

    @RequestMapping(path = "/private", method = RequestMethod.GET)
    public String privatePage(ModelMap map){
        map.addAttribute("message","This is private page");
        return "PrivatePage";
    }

    @RequestMapping(path = "/login", method = RequestMethod.GET)
    public String loginForm(){
        return "login";
    }

    @RequestMapping(path = "/logout", method = RequestMethod.GET)
    public String logoutForm(ModelMap map){
        map.addAttribute("logout", "You've Logged Out Successfully!!!!");
        return "logout";
    }


}
