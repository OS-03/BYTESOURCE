import random

from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, render
from django.utils.decorators import method_decorator
from django.views.generic import DetailView, ListView, TemplateView
from django.views.generic.edit import FormView
from django.contrib.auth.models import User
from base64 import urlsafe_b64decode, urlsafe_b64encode

from online_test import settings
from .forms import QuestionForm
from .models import Quiz, Category, Progress, Sitting, Question
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.core.mail import EmailMessage, send_mail
from django.views import View
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.views.decorators.csrf import *
from django.urls import reverse_lazy
from django.contrib.auth.views import PasswordResetView
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .tokens import generate_token


class QuizMarkerMixin(object):
    @method_decorator(login_required)
    @method_decorator(permission_required("quiz.view_sittings"))
    def dispatch(self, *args, **kwargs):
        return super(QuizMarkerMixin, self).dispatch(*args, **kwargs)


class SittingFilterTitleMixin(object):
    def get_queryset(self):
        queryset = super(SittingFilterTitleMixin, self).get_queryset()
        quiz_filter = self.request.GET.get("quiz_filter")
        if quiz_filter:
            queryset = queryset.filter(quiz__title__icontains=quiz_filter)

        return queryset


class QuizListView(ListView):
    model = Quiz

    # @login_required
    def get_queryset(self):
        queryset = super(QuizListView, self).get_queryset()
        return queryset.filter(draft=False)


class QuizDetailView(DetailView):
    model = Quiz
    slug_field = "url"

    def get(self, request, *args, **kwargs):
        self.object = self.get_object()

        if self.object.draft and not request.user.has_perm("quiz.change_quiz"):
            raise PermissionDenied

        context = self.get_context_data(object=self.object)
        return self.render_to_response(context)


class CategoriesListView(ListView):
    model = Category


class ViewQuizListByCategory(ListView):
    model = Quiz
    template_name = "view_quiz_category.html"

    def dispatch(self, request, *args, **kwargs):
        self.category = get_object_or_404(
            Category, category=self.kwargs["category_name"]
        )

        return super(ViewQuizListByCategory, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(ViewQuizListByCategory, self).get_context_data(**kwargs)

        context["category"] = self.category
        return context

    def get_queryset(self):
        queryset = super(ViewQuizListByCategory, self).get_queryset()
        return queryset.filter(category=self.category, draft=False)


class QuizUserProgressView(TemplateView):
    template_name = "progress.html"

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(QuizUserProgressView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(QuizUserProgressView, self).get_context_data(**kwargs)
        progress, c = Progress.objects.get_or_create(user=self.request.user)
        context["cat_scores"] = progress.list_all_cat_scores
        context["exams"] = progress.show_exams()
        return context


class QuizMarkingList(QuizMarkerMixin, SittingFilterTitleMixin, ListView):
    model = Sitting

    def get_queryset(self):
        queryset = super(QuizMarkingList, self).get_queryset().filter(complete=True)

        user_filter = self.request.GET.get("user_filter")
        if user_filter:
            queryset = queryset.filter(user__username__icontains=user_filter)

        return queryset

    class Meta:
        pass


class QuizMarkingDetail(QuizMarkerMixin, DetailView):
    model = Sitting

    def post(self, request, *args, **kwargs):
        sitting = self.get_object()

        q_to_toggle = request.POST.get("qid", None)
        if q_to_toggle:
            q = Question.objects.get_subclass(id=int(q_to_toggle))
            if int(q_to_toggle) in sitting.get_incorrect_questions:
                sitting.remove_incorrect_question(q)
            else:
                sitting.add_incorrect_question(q)

        return self.get(request)

    def get_context_data(self, **kwargs):
        context = super(QuizMarkingDetail, self).get_context_data(**kwargs)
        context["questions"] = context["sitting"].get_questions(with_answers=True)
        return context


class QuizTake(FormView):
    form_class = QuestionForm
    template_name = "question.html"

    def dispatch(self, request, *args, **kwargs):
        self.quiz = get_object_or_404(Quiz, url=self.kwargs["quiz_name"])
        if self.quiz.draft and not request.user.has_perm("quiz.change_quiz"):
            raise PermissionDenied

        self.logged_in_user = self.request.user.is_authenticated

        if self.logged_in_user:
            self.sitting = Sitting.objects.user_sitting(request.user, self.quiz)
        if self.sitting is False:
            return render(request, "single_complete.html")

        return super(QuizTake, self).dispatch(request, *args, **kwargs)

    def get_form(self, form_class=QuestionForm):
        if self.logged_in_user:
            self.question = self.sitting.get_first_question()
            self.progress = self.sitting.progress()
        return form_class(**self.get_form_kwargs())

    def get_form_kwargs(self):
        kwargs = super(QuizTake, self).get_form_kwargs()

        return dict(kwargs, question=self.question)

    def form_valid(self, form):
        if self.logged_in_user:
            self.form_valid_user(form)
            if self.sitting.get_first_question() is False:
                return self.final_result_user()
        self.request.POST = {}

        return super(QuizTake, self).get(self, self.request)

    def get_context_data(self, **kwargs):
        context = super(QuizTake, self).get_context_data(**kwargs)
        context["question"] = self.question
        context["quiz"] = self.quiz
        if hasattr(self, "previous"):
            context["previous"] = self.previous
        if hasattr(self, "progress"):
            context["progress"] = self.progress
        return context

    def form_valid_user(self, form):
        progress, c = Progress.objects.get_or_create(user=self.request.user)
        guess = form.cleaned_data["answers"]
        is_correct = self.question.check_if_correct(guess)

        if is_correct is True:
            self.sitting.add_to_score(1)
            progress.update_score(self.question, 1, 1)
        else:
            self.sitting.add_incorrect_question(self.question)
            progress.update_score(self.question, 0, 1)

        if self.quiz.answers_at_end is not True:
            self.previous = {
                "previous_answer": guess,
                "previous_outcome": is_correct,
                "previous_question": self.question,
                "answers": self.question.get_answers(),
                "question_type": {self.question.__class__.__name__: True},
            }
        else:
            self.previous = {}

        self.sitting.add_user_answer(self.question, guess)
        self.sitting.remove_first_question()

    def final_result_user(self):
        results = {
            "quiz": self.quiz,
            "score": self.sitting.get_current_score,
            "max_score": self.sitting.get_max_score,
            "percent": self.sitting.get_percent_correct,
            "sitting": self.sitting,
            "previous": self.previous,
        }

        self.sitting.mark_quiz_complete()

        if self.quiz.answers_at_end:
            results["questions"] = self.sitting.get_questions(with_answers=True)
            results["incorrect_questions"] = self.sitting.get_incorrect_questions

        if self.quiz.exam_paper is False:
            self.sitting.delete()

        return render(self.request, "result.html", results)


def index(request):
    return render(request, "index.html", {})


def signup_user(request):

    if request.method == "POST":
        username = request.POST["username"]
        fname = request.POST["fname"]
        lname = request.POST["lname"]
        email = request.POST["email"]
        pass1 = request.POST["pass1"]
        pass2 = request.POST["pass2"]

        if User.objects.filter(username=username):
            messages.error(
                request, "Username already exist! Please try some other username"
            )
            return redirect("signup")

        if User.objects.filter(email=email):
            messages.error(request, "Username must be under 10 character")

        if len(username) > 20:
            messages.error(request, "Username must be under 20 charcters!!")
            return redirect("signup")

        if pass1 != pass2:
            messages.error(request, "Passwords didn't matched!!")
            return redirect("signup")

        if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric!!")
            return redirect("signup")

        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = True
        myuser.save()
        messages.success(
            request,
            "Your Account has been created succesfully!! Please check your email to confirm your email address in order to activate your account.",
        )

        # Welcome Email
        subject = "Welcome to BYTESOURCE-Login!!"
        message = (
            "Hello "
            + myuser.first_name
            + "!! \n"
            + "Welcome to  BYTESOURCE !! \nThank you for visiting our website\n. We have also sent you a confirmation email, please confirm your email address. \n\nThanking You\nAnubhav Madhav"
        )
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        # Email Address Confirmation Email
        current_site = get_current_site(request)
        email_subject = "Confirm your Email !!"
        message2 = render_to_string(
            "email_confirmation.html",
            {
                "name": myuser.first_name,
                "domain": current_site.domain,
                "uid": urlsafe_b64encode(force_bytes(myuser.pk)),
                "token": generate_token.make_token(myuser),
            },
        )

        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        # email.fail_silently = True
        # email.send()

        login(request, myuser)
        return redirect("index")

    return render(request, "signup.html")


def login_user(request):

    if request.method == "POST":
        username = request.POST["username"]
        pass1 = request.POST["pass1"]
        user = authenticate(request, username=username, password=pass1)
        if user is not None:
            login(request, user)
            messages.success(request, "You have successfully logged in")
            return redirect("index")
        else:
            messages.success(request, "Error logging in")
            return redirect("login")
    else:
        return render(request, "login.html", {})


def logout_user(request):
    logout(request)
    # messages.success(request, 'You have been logged out!')
    # print('logout function working')
    return redirect("login")


def activate(request, uidb64, token):
    try:
        uid = force_bytes(urlsafe_b64decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        login(request, myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect("base")
    else:
        return render(request, "activation_failed.html")


def Go(request):
    return render(request, "Go.html", {})


from .models import ThemeConfiguration


def theme(request):
    if request.user.is_authenticated:
        _theme = ThemeConfiguration.objects.filter(user=request.user).last()
    else:
        _theme = None
    return {
        "theme": _theme,
    }


def dsa(request):
    return render(request, "dsa.html", {})


def dsa1(request):
    return render(request, "dsa1.html", {})


def dsa2(request):
    return render(request, "dsa2.html", {})


def dsa3(request):
    return render(request, "dsa3.html", {})


def dsa4(request):
    return render(request, "dsa4.html", {})


def dsa5(request):
    return render(request, "dsa5.html", {})


def dsa6(request):
    return render(request, "dsa6.html", {})


def os(request):
    return render(request, "os.html", {})


def os1(request):
    return render(request, "os1.html", {})


def os2(request):
    return render(request, "os2.html", {})


def os3(request):
    return render(request, "os3.html", {})


def os4(request):
    return render(request, "os4.html", {})


def os5(request):
    return render(request, "os5.html", {})


def sql(request):
    return render(request, "sql.html", {})


def sql1(request):
    return render(request, "sql1.html", {})


def sql2(request):
    return render(request, "sql2.html", {})


def sql3(request):
    return render(request, "sql3.html", {})


def sql4(request):
    return render(request, "sql4.html", {})


def sql5(request):
    return render(request, "sql5.html", {})


def toc(request):
    return render(request, "toc.html", {})


def toc1(request):
    return render(request, "toc1.html", {})


def toc2(request):
    return render(request, "toc2.html", {})


def toc3(request):
    return render(request, "toc3.html", {})


def toc4(request):
    return render(request, "toc4.html", {})


def toc5(request):
    return render(request, "toc5.html", {})


def cn(request):
    return render(request, "cn.html", {})


def cn1(request):
    return render(request, "cn1.html", {})


def cn2(request):
    return render(request, "cn2.html", {})


def cn3(request):
    return render(request, "cn3.html", {})


def cn4(request):
    return render(request, "cn4.html", {})


def cn5(request):
    return render(request, "cn5.html", {})


def cn6(request):
    return render(request, "cn6.html", {})


def admin(request):
    return redirect("/admin/")


def redirect_to_admin(request):
    return render(request, "quiz/redirect_to_admin.html", {})


# def main_page(request):
#     return render(request, 'quiz/main_page.html')
